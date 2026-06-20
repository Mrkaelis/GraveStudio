"""
GraveStudio — Flask app
Sait s admin-panel'yu, OAuth (Google + Discord) i email/parol.
"""
import os
import json
import time
import random
import secrets
import string
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlencode

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    abort, jsonify, session, send_from_directory, make_response
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from authlib.integrations.flask_client import OAuth
from sqlalchemy import inspect, text as sa_text

# Категории сборок, по которым пользователи оставляют отзывы.
REVIEW_CATEGORIES = ["RW Defaults", "RW Full", "RW Premium"]

load_dotenv()

# ---------------------------------------------------------------------------
# App / DB
# ---------------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")

# Railway (и большинство хостингов) даёт адрес БД через переменную окружения
# DATABASE_URL. Если её нет — используем локальный файл SQLite (для разработки
# на своём компьютере). На Railway просто добавьте плагин PostgreSQL и
# привяжите (Variable Reference) ${{Postgres.DATABASE_URL}} к этому сервису —
# переменная подхватится сама, ничего в коде менять не нужно.
_database_url = os.getenv("DATABASE_URL", "").strip()
if _database_url:
    # Старые версии psycopg2/SQLAlchemy не понимают префикс "postgres://",
    # его нужно заменить на "postgresql://" (Railway иногда даёт именно его).
    if _database_url.startswith("postgres://"):
        _database_url = _database_url.replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = _database_url
else:
    os.makedirs(os.path.join(BASE_DIR, "instance"), exist_ok=True)
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        "sqlite:///" + os.path.join(BASE_DIR, "instance", "gravestudio.db")
    )

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,  # переподключается, если Postgres разорвал «протухшее» соединение
}

# Session security
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
# In production set SESSION_COOKIE_SECURE=True via env
if os.getenv("FLASK_ENV") == "production":
    app.config["SESSION_COOKIE_SECURE"] = True

# ---------------------------------------------------------------------------
# Загрузка файлов (логотип, фоновая картинка сайта)
# ---------------------------------------------------------------------------
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "webp", "svg"}
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8 МБ на запрос (картинки настроек)


def _save_upload(file_storage):
    """Сохраняет загруженную картинку в static/uploads и возвращает её URL, либо None."""
    if not file_storage or not file_storage.filename:
        return None
    filename = secure_filename(file_storage.filename)
    if "." not in filename:
        return None
    ext = filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_IMAGE_EXT:
        return None
    new_name = f"{uuid.uuid4().hex}.{ext}"
    file_storage.save(os.path.join(UPLOAD_FOLDER, new_name))
    return url_for("static", filename=f"uploads/{new_name}")

# OAuth dev: razreshaem http callback
if os.getenv("FLASK_DEBUG") == "1":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "auth_page"

# ---------------------------------------------------------------------------
# Жёстко вписанный список суперадминов (помимо ADMIN_EMAILS в .env)
# ---------------------------------------------------------------------------
HARDCODED_ADMINS = {
    "dimacontrol2223@gmail.com",
}

# ---------------------------------------------------------------------------
# Rate limiting — простой in-memory счётчик (для продакшна замените на Flask-Limiter + Redis)
# ---------------------------------------------------------------------------
_login_attempts: dict = defaultdict(list)  # ip -> [timestamp, ...]

RATE_LIMIT_ATTEMPTS = int(os.getenv("RATE_LIMIT_ATTEMPTS", "5"))   # попыток
RATE_LIMIT_WINDOW  = int(os.getenv("RATE_LIMIT_WINDOW",   "300"))  # секунд (5 мин)
RATE_LIMIT_LOCKOUT = int(os.getenv("RATE_LIMIT_LOCKOUT",  "900"))  # секунд блокировки (15 мин)

_lockouts: dict = {}  # ip -> locked_until (unix time)


def _client_ip():
    # За обратным прокси (nginx) читаем X-Forwarded-For
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _is_locked(ip: str) -> bool:
    until = _lockouts.get(ip)
    if until and time.time() < until:
        return True
    _lockouts.pop(ip, None)
    return False


def _record_failed(ip: str):
    now = time.time()
    # Чистим старые попытки
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < RATE_LIMIT_WINDOW]
    _login_attempts[ip].append(now)
    if len(_login_attempts[ip]) >= RATE_LIMIT_ATTEMPTS:
        _lockouts[ip] = now + RATE_LIMIT_LOCKOUT
        _login_attempts[ip] = []


def _clear_attempts(ip: str):
    _login_attempts.pop(ip, None)
    _lockouts.pop(ip, None)


# ---------------------------------------------------------------------------
# Защита от копирования / дампа сайта (анти-скрейпинг)
# ---------------------------------------------------------------------------
# Полностью выключить (например, для локальной разработки/тестов curl-ом):
# поставьте в .env  DISABLE_ANTI_SCRAPE=1
ANTI_SCRAPE_ENABLED = os.getenv("DISABLE_ANTI_SCRAPE", "0") != "1"

# Известные инструменты для скачивания/парсинга сайтов целиком — блокируем.
BLOCKED_UA_SUBSTRINGS = [
    # HTTP-клиенты и скрипты
    "python-requests", "curl/", "wget/", "libwww-perl", "go-http-client",
    "okhttp", "node-fetch", "axios/", "postmanruntime", "aiohttp", "httpie",
    "java/", "ruby", "php/", "perl/", "powershell", "winhttp", "httpclient",
    "urllib", "guzzlehttp", "rest-client", "lwp::", "mechanize",
    # Скрейперы / дампилки сайтов целиком
    "scrapy", "httrack", "site-shot", "screaming frog", "webcopier",
    "teleport", "siteexplorer", "wget", "offline explorer", "webreaper",
    "webzip", "black widow", "getleft", "siteSucker", "larbin", "webripper",
    "grabber", "copier", "downloader", "extractor", "harvest", "crawler4j",
    "spider", "scraper", "datacollector", "content grabber",
    # Сетевые сканеры / разведка / эксплойт-тулзы
    "masscan", "nmap", "sqlmap", "nikto", "zgrab", "nuclei", "wpscan",
    "dirbuster", "gobuster", "ffuf", "burpsuite", "acunetix", "nessus",
    "qualys", "metasploit", "shodan", "censys", "zmap",
    # SEO/маркетинговые боты, которые массово дампят сайты
    "ahrefsbot", "semrushbot", "mj12bot", "dotbot", "petalbot", "blexbot",
    "megaindex", "serpstatbot", "linkpadbot", "seokicks", "rogerbot",
    "exabot", "sogou", "proximic", "barkrowler", "cocolyzebot",
    # AI-краулеры, забирающие контент для обучения моделей без разрешения
    "gptbot", "ccbot", "claudebot", "anthropic-ai", "bytespider",
    "google-extended", "ia_archiver", "diffbot", "omgili", "timpibot",
]
# Легитимные поисковые/соцсетевые боты — их не трогаем (нужны для SEO/превью ссылок).
GOOD_BOT_SUBSTRINGS = [
    "googlebot", "bingbot", "yandexbot", "duckduckbot",
    "facebookexternalhit", "telegrambot", "applebot", "slurp",
    "whatsapp", "vkshare", "discordbot",
]
# Блокировать запросы вообще без заголовка User-Agent (почти всегда — скрипт).
BLOCK_EMPTY_USER_AGENT = True

# Лимит запросов с одного IP на «обычные» страницы — чтобы нельзя было
# быстро скачать («задампить») весь сайт скриптом.
_page_requests: dict = defaultdict(list)  # ip -> [timestamp, ...]
SCRAPE_RATE_LIMIT  = int(os.getenv("SCRAPE_RATE_LIMIT",  "120"))  # запросов
SCRAPE_RATE_WINDOW = int(os.getenv("SCRAPE_RATE_WINDOW", "60"))   # за N секунд

# Бан по IP за нарушения (попался под UA-фильтр, honeypot-путь, флуд) —
# в отличие от обычного 403 на один запрос, при бане блокируются ВСЕ
# последующие запросы этого IP на заданное время.
_scrape_bans: dict = {}  # ip -> banned_until (unix time)
SCRAPE_BAN_SECONDS = int(os.getenv("SCRAPE_BAN_SECONDS", "3600"))  # 1 час

# «Капканные» пути — их не видно ни в одной ссылке на сайте и не существует
# в реальности; настоящий человек туда никогда не попадёт. Боты, которые
# сканируют сайт по словарю путей (wp-admin, .env, .git и т.п.) или ходят по
# всем ссылкам подряд, рано или поздно задевают один из них и банятся сразу.
HONEYPOT_PATHS = {
    "/wp-admin", "/wp-login.php", "/wp-content", "/wp-includes",
    "/.env", "/.env.local", "/.env.production", "/.git/config", "/.git/HEAD",
    "/config.php", "/config.json", "/configuration.php",
    "/phpmyadmin", "/pma", "/adminer.php", "/server-status",
    "/.aws/credentials", "/.ssh/id_rsa", "/id_rsa",
    "/backup.sql", "/backup.zip", "/dump.sql", "/database.sql", "/db.sql",
    "/api/v1/users", "/xmlrpc.php", "/.well-known/security.txt~",
    "/vendor/phpunit", "/.htaccess", "/web.config",
}


def _is_banned(ip: str) -> bool:
    until = _scrape_bans.get(ip)
    if until and time.time() < until:
        return True
    _scrape_bans.pop(ip, None)
    return False


def _ban_ip(ip: str, seconds: int = SCRAPE_BAN_SECONDS):
    _scrape_bans[ip] = time.time() + seconds


def _is_blocked_ua(ua: str) -> bool:
    ua = (ua or "").strip().lower()
    if not ua:
        return BLOCK_EMPTY_USER_AGENT
    if any(g in ua for g in GOOD_BOT_SUBSTRINGS):
        return False
    return any(b in ua for b in BLOCKED_UA_SUBSTRINGS)


# ---------------------------------------------------------------------------
# Honeypot — анти-бот защита публичных форм (логин/регистрация/отзывы/gate)
# ---------------------------------------------------------------------------
HONEYPOT_FIELD = "company_site"  # «приманка»: реальный человек это поле не видит и не трогает
MIN_FORM_SECONDS = 2             # форма, отправленная быстрее — почти наверняка бот


def _honeypot_passed() -> bool:
    """True, если форму заполнял человек, а не бот."""
    if (request.form.get(HONEYPOT_FIELD) or "").strip():
        return False
    ts = request.form.get("form_ts")
    if ts:
        try:
            if time.time() - float(ts) < MIN_FORM_SECONDS:
                return False
        except (TypeError, ValueError):
            pass
    return True


# ---------------------------------------------------------------------------
# Капча — простая математическая проверка «я не бот».
# Полностью самодостаточная (без внешних сервисов/API-ключей/JS-виджетов),
# поэтому не может «упасть» из-за недоступности стороннего сервиса.
# Используется на входе, регистрации и отправке отзыва.
# ---------------------------------------------------------------------------
CAPTCHA_TTL = 600  # секунд, сколько действует один вопрос капчи


def new_captcha() -> str:
    """Генерирует новый вопрос, кладёт ответ в сессию и возвращает текст вопроса."""
    a, b = random.randint(1, 9), random.randint(1, 9)
    op = random.choice(["+", "-"])
    if op == "-" and a < b:
        a, b = b, a
    answer = a + b if op == "+" else a - b
    session["captcha_answer"] = answer
    session["captcha_ts"] = time.time()
    return f"{a} {op} {b} = ?"


def _captcha_passed() -> bool:
    """True, если ответ на капчу из формы верный и вопрос не протух."""
    expected = session.pop("captcha_answer", None)
    ts = session.pop("captcha_ts", None)
    if expected is None or ts is None:
        return False
    if time.time() - ts > CAPTCHA_TTL:
        return False
    given = (request.form.get("captcha_answer") or "").strip()
    try:
        return int(given) == int(expected)
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255))
    avatar_url = db.Column(db.String(500))
    password_hash = db.Column(db.String(255))  # nullable for OAuth users
    provider = db.Column(db.String(50), default="email")  # email|google|discord
    is_admin = db.Column(db.Boolean, default=False)
    balance = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def check_password(self, pw):
        return self.password_hash and check_password_hash(self.password_hash, pw)


class Setting(db.Model):
    """key -> value (JSON-string). Universal store for site config."""
    key = db.Column(db.String(100), primary_key=True)
    value = db.Column(db.Text)


class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    price = db.Column(db.String(100))
    description = db.Column(db.Text)
    order = db.Column(db.Integer, default=0)


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    category = db.Column(db.String(50), default=REVIEW_CATEGORIES[0], index=True)
    author = db.Column(db.String(200))
    text = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, default=5)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class NewsItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Partner(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500))
    logo_url = db.Column(db.String(500))


class Build(db.Model):
    """Сборка ReallyWorld, доступная для покупки с баланса (RW Default / RW Full / RW Premium и т.д.)."""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    tier_label = db.Column(db.String(50), default="")     # напр. "TIER 01"
    price = db.Column(db.Integer, nullable=False, default=0)
    description = db.Column(db.Text)
    download_url = db.Column(db.String(1000))              # ссылка, которая выдаётся после покупки
    is_active = db.Column(db.Boolean, default=True)        # можно временно скрыть из продажи
    order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Purchase(db.Model):
    """Запись о покупке сборки пользователем — даёт доступ к ссылке в «Моих сборках»."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    build_id = db.Column(db.Integer, db.ForeignKey("build.id"), nullable=False, index=True)
    price_paid = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User")
    build = db.relationship("Build")


class RedeemCode(db.Model):
    """Ключ пополнения баланса: генерируется в админ-панели, активируется пользователем один раз."""
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(40), unique=True, nullable=False, index=True)
    amount = db.Column(db.Integer, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    used_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    used_at = db.Column(db.DateTime)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    used_by = db.relationship("User", foreign_keys=[used_by_id])
    created_by = db.relationship("User", foreign_keys=[created_by_id])


# ---------------------------------------------------------------------------
# Settings helpers
# ---------------------------------------------------------------------------
DEFAULT_SETTINGS = {
    "brand_name": "GraveStudio - Лучшая студия!",
    "brand_tagline": "Мы строим качество, которое работает на вас.",
    "brand_logo": "https://cdn.discordapp.com/attachments/1511411379008176229/1516750689249005608/wNWOpAAAABklEQVQDAKF8cyz8ABcAAAAAElFTkSuQmCC.png?ex=6a33c7a8&is=6a327628&hm=d2de6a6cb9a0374a2b6eb714c04512f65cf50565bec59e65e17d3ceccc96f127&",
    "hero_title": "GraveStudio",
    "hero_subtitle": "Каждое решение GraveStudio — для вашего уверенного роста.",
    "hero_cta_text": "Связаться",
    "about_text": (
        "Наша миссия — разрабатывать сборки ReallyWorld, которые не просто функционируют, а становятся основой успешного проекта. Мы уделяем внимание каждой детали, обеспечивая высочайшую оптимизацию и бесперебойную работу вашего сервера. Вы получите продукт, созданный с заботой о ваших целях. "
        "Мы работаем чисто, в срок и с гарантией."
    ),
    "background_color": "#0b0b12",
    "background_image": "",
    "accent_color": "#7c3aed",
    "link_discord": "https://discord.gg/",
    "link_telegram": "https://t.me/officialGraveStudio",
    "link_funpay": "https://funpay.com/users/17053232/",
    "link_support": "https://t.me/GraveStudioSupport",
    "maintenance": "0",
    "maintenance_text": "Сайт на технических работах. Скоро вернёмся.",
    "particle_effect": "none",
}

# Пароль доп.экрана перед админ-панелью
ADMIN_GATE_PASSWORD = os.getenv("ADMIN_GATE_PASSWORD", "123wue123.")


@app.context_processor
def inject_helpers():
    return {"now_year": lambda: datetime.utcnow().year, "form_ts": time.time()}


def get_setting(key, default=None):
    row = Setting.query.get(key)
    if row is None:
        return DEFAULT_SETTINGS.get(key, default)
    return row.value


def set_setting(key, value):
    row = Setting.query.get(key)
    if row is None:
        row = Setting(key=key, value=value)
        db.session.add(row)
    else:
        row.value = value


@app.context_processor
def inject_globals():
    """Делает settings + links доступными во всех шаблонах."""
    def s(k):
        return get_setting(k, "")
    return {
        "S": s,
        "site_links": {
            "discord": s("link_discord"),
            "telegram": s("link_telegram"),
            "funpay": s("link_funpay"),
            "support": s("link_support"),
        },
        "brand_name": s("brand_name"),
        "brand_tagline": s("brand_tagline"),
        "brand_logo": s("brand_logo"),
        "accent_color": s("accent_color") or "#7c3aed",
        "background_color": s("background_color") or "#0b0b12",
        "background_image": s("background_image"),
        "particle_effect": s("particle_effect") or "none",
        "current_user": current_user,
    }


@app.template_filter("money")
def money_filter(value):
    """Форматирует число с пробелами как разделителями тысяч: 1250 -> '1 250'."""
    try:
        value = int(value or 0)
    except (TypeError, ValueError):
        value = 0
    return f"{value:,}".replace(",", " ")


# ---------------------------------------------------------------------------
# Security headers — добавляются ко всем ответам
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

    # Не выдавать поисковикам/архиваторам страницы админки и служебных разделов —
    # лишний способ найти их через выдачу поиска или веб-архив.
    if request.endpoint and (
        request.endpoint.startswith("admin_") or request.endpoint == "admin_gate_page"
    ):
        response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive, nosnippet"

    # Скрываем версию сервера/фреймворка — не даём атакующему лёгкую подсказку,
    # под какую конкретную версию Werkzeug/gunicorn искать готовые эксплойты.
    if "Server" in response.headers:
        response.headers["Server"] = "GraveStudio"

    # Строгий CSP только для продакшна; в дев-режиме он может мешать
    if os.getenv("FLASK_ENV") == "production":
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self';"
        )
    if os.getenv("FLASK_ENV") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ---------------------------------------------------------------------------
# Анти-скрейп: блокировка известных парсеров/скриптов и троттлинг по IP.
# Цель — не дать быстро «скачать» (задампить) весь сайт автоматическим
# инструментом. От ручного просмотра страницы в браузере это не защищает,
# для этого есть клиентская защита (static/js/protect.js).
# ---------------------------------------------------------------------------
@app.before_request
def anti_scrape_guard():
    if not ANTI_SCRAPE_ENABLED:
        return
    if request.endpoint == "static":
        return

    ip = _client_ip()

    # Если IP уже забанен за предыдущее нарушение — сразу отказ,
    # без дополнительных проверок.
    if _is_banned(ip):
        abort(403)

    # Капкан: путь, на который никогда не ведёт ни одна ссылка сайта.
    # Сюда попадают только боты, перебирающие типовые/уязвимые пути.
    path_lower = request.path.lower().rstrip("/")
    if path_lower in HONEYPOT_PATHS or any(
        path_lower.startswith(h.rstrip("/")) for h in HONEYPOT_PATHS
    ):
        _ban_ip(ip)
        abort(403)

    ua = request.headers.get("User-Agent", "")
    if _is_blocked_ua(ua):
        # Известный скрейпер/дамп-инструмент — баним сразу, а не просто
        # отказываем в этом одном запросе (иначе скрипт просто повторит попытку).
        _ban_ip(ip)
        abort(403)

    now = time.time()
    bucket = _page_requests[ip]
    bucket[:] = [t for t in bucket if now - t < SCRAPE_RATE_WINDOW]
    bucket.append(now)
    if len(bucket) > SCRAPE_RATE_LIMIT:
        # Слишком много запросов за окно — похоже на массовое скачивание
        # сайта скриптом. Баним IP на длительный срок, а не только текущий запрос.
        _ban_ip(ip)
        abort(429)


@app.errorhandler(403)
def handle_403(e):
    return render_template(
        "blocked.html", code=403, title="Доступ запрещён",
        message="Запрос похож на автоматический скрипт или парсер и был заблокирован системой защиты сайта.",
    ), 403


@app.errorhandler(429)
def handle_429(e):
    return render_template(
        "blocked.html", code=429, title="Слишком много запросов",
        message="Слишком много запросов с вашего адреса за короткое время. Подождите немного и обновите страницу.",
    ), 429


@app.route("/robots.txt")
def robots_txt():
    lines = [
        "User-agent: *",
        "Allow: /",
        "Disallow: /admin",
        "Disallow: /auth",
        "",
        "# Боты-краулеры, замеченные в массовом скачивании/копировании сайтов",
        "User-agent: AhrefsBot",
        "Disallow: /",
        "User-agent: SemrushBot",
        "Disallow: /",
        "User-agent: MJ12bot",
        "Disallow: /",
        "User-agent: DotBot",
        "Disallow: /",
        "User-agent: PetalBot",
        "Disallow: /",
        "User-agent: ia_archiver",
        "Disallow: /",
        "User-agent: HTTrack",
        "Disallow: /",
        "",
        "# AI-краулеры, забирающие контент для обучения моделей",
        "User-agent: GPTBot",
        "Disallow: /",
        "User-agent: CCBot",
        "Disallow: /",
        "User-agent: ClaudeBot",
        "Disallow: /",
        "User-agent: Bytespider",
        "Disallow: /",
        "User-agent: Google-Extended",
        "Disallow: /",
    ]
    return make_response("\n".join(lines), 200, {"Content-Type": "text/plain; charset=utf-8"})


# ---------------------------------------------------------------------------
# Login manager
# ---------------------------------------------------------------------------
@login_manager.user_loader
def load_user(uid):
    return User.query.get(int(uid))


def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not current_user.is_authenticated:
            return redirect(url_for("auth_page", next=request.path))
        if not current_user.is_admin:
            return render_template("no_access.html"), 403
        return f(*a, **kw)
    return w


# ---------------------------------------------------------------------------
# Доп. защита /admin паролем (отдельно от логина/is_admin).
# ---------------------------------------------------------------------------
@app.before_request
def admin_gate():
    if not request.endpoint:
        return
    if request.endpoint in ("admin_gate_page", "static", "logout"):
        return
    if request.endpoint.startswith("admin_") and not session.get("admin_gate_ok"):
        session["admin_gate_next"] = request.path
        return redirect(url_for("admin_gate_page"))


@app.route("/admin/gate", methods=["GET", "POST"])
def admin_gate_page():
    ip = _client_ip()
    if _is_locked(ip):
        remaining = int(_lockouts.get(ip, 0) - time.time())
        flash(f"Слишком много попыток. Подождите {remaining // 60} мин {remaining % 60} сек.", "error")
        return render_template("admin/gate.html")

    if request.method == "POST":
        if not _honeypot_passed():
            _record_failed(ip)
            flash("Неверный пароль доступа к админ-панели.", "error")
            return render_template("admin/gate.html")

        pw = request.form.get("password", "")
        if pw == ADMIN_GATE_PASSWORD:
            _clear_attempts(ip)
            session["admin_gate_ok"] = True
            nxt = session.pop("admin_gate_next", None) or url_for("admin_home")
            return redirect(nxt)
        _record_failed(ip)
        flash("Неверный пароль доступа к админ-панели.", "error")
    return render_template("admin/gate.html")


# ---------------------------------------------------------------------------
# Maintenance gate
# ---------------------------------------------------------------------------
@app.before_request
def maintenance_gate():
    if request.endpoint in (None, "static"):
        return
    allowed = {
        "auth_page", "logout", "login_email", "register_email",
        "oauth_login", "oauth_callback", "static",
    }
    if request.endpoint and (
        request.endpoint in allowed
        or request.endpoint.startswith("admin_")
    ):
        return
    if get_setting("maintenance", "0") == "1":
        if current_user.is_authenticated and current_user.is_admin:
            return
        return render_template(
            "maintenance.html",
            text=get_setting("maintenance_text", ""),
        ), 503


# ---------------------------------------------------------------------------
# OAuth (Authlib)
# ---------------------------------------------------------------------------
oauth = OAuth(app)

if os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"):
    oauth.register(
        name="google",
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

if os.getenv("DISCORD_CLIENT_ID") and os.getenv("DISCORD_CLIENT_SECRET"):
    oauth.register(
        name="discord",
        client_id=os.getenv("DISCORD_CLIENT_ID"),
        client_secret=os.getenv("DISCORD_CLIENT_SECRET"),
        access_token_url="https://discord.com/api/oauth2/token",
        authorize_url="https://discord.com/api/oauth2/authorize",
        api_base_url="https://discord.com/api/",
        client_kwargs={"scope": "identify email"},
    )


def has_provider(name):
    return name in oauth._clients


@app.context_processor
def inject_providers():
    return {
        "providers": {
            "google": has_provider("google"),
            "discord": has_provider("discord"),
        }
    }


def _redirect_uri(provider):
    base = os.getenv("OAUTH_REDIRECT_BASE", "").rstrip("/")
    path = url_for("oauth_callback", provider=provider)
    if base:
        return base + path
    return request.url_root.rstrip("/") + path


def _is_admin_email(email: str) -> bool:
    """Проверяет, является ли email суперадмином."""
    email = email.lower().strip()
    if email in HARDCODED_ADMINS:
        return True
    seed_admins = {
        e.strip().lower()
        for e in os.getenv("ADMIN_EMAILS", "").split(",")
        if e.strip()
    }
    return email in seed_admins


def _finalize_login(email, name, avatar, provider):
    email = (email or "").lower().strip()
    if not email:
        flash("Не удалось получить email от провайдера.", "error")
        return redirect(url_for("auth_page"))

    user = User.query.filter_by(email=email).first()
    is_first = User.query.count() == 0

    if not user:
        user = User(email=email, name=name or email.split("@")[0],
                    avatar_url=avatar or "", provider=provider)
        db.session.add(user)

    if is_first or _is_admin_email(email):
        user.is_admin = True
    if name and not user.name:
        user.name = name
    if avatar:
        user.avatar_url = avatar
    user.provider = provider
    db.session.commit()

    login_user(user, remember=True)
    flash(f"Добро пожаловать, {user.name or user.email}!", "ok")
    nxt = session.pop("post_login_next", None) or url_for("index")
    return redirect(nxt)


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    services = Service.query.order_by(Service.order, Service.id).all()

    reviews_by_cat = {}
    avg_ratings = {}
    for cat in REVIEW_CATEGORIES:
        items = Review.query.filter_by(category=cat).order_by(Review.created_at.desc()).all()
        reviews_by_cat[cat] = items
        avg_ratings[cat] = round(sum(r.rating for r in items) / len(items), 1) if items else None

    user_reviews = {}
    if current_user.is_authenticated:
        for r in Review.query.filter_by(user_id=current_user.id).all():
            user_reviews[r.category] = r

    news = NewsItem.query.order_by(NewsItem.created_at.desc()).limit(3).all()
    partners = Partner.query.order_by(Partner.id).all()
    builds = Build.query.filter_by(is_active=True).order_by(Build.order, Build.id).all()
    return render_template(
        "index.html", services=services,
        review_categories=REVIEW_CATEGORIES,
        reviews_by_cat=reviews_by_cat, avg_ratings=avg_ratings,
        user_reviews=user_reviews,
        news=news, partners=partners, builds=builds,
        captcha_question=new_captcha(),
    )


@app.route("/about")
def about():
    return render_template("about.html", about_text=get_setting("about_text", ""))


@app.route("/partners")
def partners_page():
    partners = Partner.query.order_by(Partner.id).all()
    return render_template("partners.html", partners=partners)


# ---------------------------------------------------------------------------
# User reviews
# ---------------------------------------------------------------------------
@app.route("/reviews/add", methods=["POST"])
@login_required
def add_review():
    if not _honeypot_passed():
        return redirect(url_for("index") + "#reviews")

    if not _captcha_passed():
        flash("Неверный ответ на капчу. Попробуйте ещё раз.", "error")
        return redirect(url_for("index") + "#reviews")

    category = (request.form.get("category") or "").strip()
    if category not in REVIEW_CATEGORIES:
        abort(400)

    try:
        rating = int(request.form.get("rating") or 0)
    except ValueError:
        rating = 0
    if rating < 1 or rating > 5:
        flash("Выберите оценку от 1 до 5 звёзд.", "error")
        return redirect(url_for("index") + "#reviews")

    text_val = (request.form.get("text") or "").strip()
    if not text_val:
        flash("Текст отзыва не может быть пустым.", "error")
        return redirect(url_for("index") + "#reviews")

    review = Review.query.filter_by(user_id=current_user.id, category=category).first()
    if review:
        review.rating = rating
        review.text = text_val
        review.author = current_user.name or current_user.email
        review.created_at = datetime.utcnow()
        flash(f"Отзыв на «{category}» обновлён.", "ok")
    else:
        db.session.add(Review(
            user_id=current_user.id,
            category=category,
            author=current_user.name or current_user.email,
            text=text_val,
            rating=rating,
        ))
        flash(f"Спасибо за отзыв на «{category}»!", "ok")
    db.session.commit()
    return redirect(url_for("index") + "#reviews")


@app.route("/reviews/delete", methods=["POST"])
@login_required
def delete_review():
    category = (request.form.get("category") or "").strip()
    review = Review.query.filter_by(user_id=current_user.id, category=category).first()
    if review:
        db.session.delete(review)
        db.session.commit()
        flash("Отзыв удалён.", "ok")
    return redirect(url_for("index") + "#reviews")


# ---------------------------------------------------------------------------
# Баланс — активация ключей пополнения
# ---------------------------------------------------------------------------
@app.route("/balance/redeem", methods=["POST"])
@login_required
def redeem_code():
    code = (request.form.get("code") or "").strip().upper()
    nxt = request.form.get("next") or request.referrer or url_for("index")

    if not code:
        flash("Введите код активации.", "error")
        return redirect(nxt)

    rc = RedeemCode.query.filter_by(code=code).first()
    if not rc:
        flash("Такой код не найден.", "error")
    elif rc.is_used:
        flash("Этот код уже был активирован ранее.", "error")
    else:
        rc.is_used = True
        rc.used_by_id = current_user.id
        rc.used_at = datetime.utcnow()
        current_user.balance = (current_user.balance or 0) + rc.amount
        db.session.commit()
        flash(f"Код активирован! Баланс пополнен на {rc.amount} ₽.", "ok")

    return redirect(nxt)


# ---------------------------------------------------------------------------
# Покупка сборок за баланс
# ---------------------------------------------------------------------------
@app.route("/builds/<int:build_id>/buy", methods=["POST"])
@login_required
def buy_build(build_id):
    build = Build.query.get_or_404(build_id)
    if not build.is_active:
        flash("Эта сборка сейчас недоступна для покупки.", "error")
        return redirect(url_for("index") + "#rw-buttons")

    if (current_user.balance or 0) < build.price:
        flash(
            f"Недостаточно средств на балансе. Нужно {build.price} ₽, "
            f"у вас {current_user.balance or 0} ₽. Пополните баланс через FunPay.",
            "error",
        )
        return redirect(url_for("index") + "#rw-buttons")

    current_user.balance = (current_user.balance or 0) - build.price
    purchase = Purchase(user_id=current_user.id, build_id=build.id, price_paid=build.price)
    db.session.add(purchase)
    db.session.commit()

    flash(f"Сборка «{build.title}» успешно куплена!", "ok")
    return redirect(url_for("my_builds"))


@app.route("/my-builds")
@login_required
def my_builds():
    purchases = (
        Purchase.query.filter_by(user_id=current_user.id)
        .order_by(Purchase.created_at.desc())
        .all()
    )
    return render_template("my_builds.html", purchases=purchases)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
@app.route("/auth", methods=["GET"])
def auth_page():
    nxt = request.args.get("next")
    if nxt:
        session["post_login_next"] = nxt
    return render_template("auth.html", captcha_question=new_captcha())


@app.route("/auth/login", methods=["POST"])
def login_email():
    ip = _client_ip()
    if _is_locked(ip):
        remaining = int(_lockouts.get(ip, 0) - time.time())
        flash(f"Слишком много попыток входа. Подождите {remaining // 60} мин {remaining % 60} сек.", "error")
        return redirect(url_for("auth_page"))

    if not _honeypot_passed():
        _record_failed(ip)
        flash("Неверный email или пароль.", "error")
        return redirect(url_for("auth_page"))

    if not _captcha_passed():
        _record_failed(ip)
        flash("Неверный ответ на капчу. Попробуйте ещё раз.", "error")
        return redirect(url_for("auth_page"))

    email = (request.form.get("email") or "").lower().strip()
    pw = request.form.get("password") or ""
    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(pw):
        _record_failed(ip)
        flash("Неверный email или пароль.", "error")
        return redirect(url_for("auth_page"))

    _clear_attempts(ip)
    login_user(user, remember=True)
    return redirect(session.pop("post_login_next", None) or url_for("index"))


@app.route("/auth/register", methods=["POST"])
def register_email():
    if not _honeypot_passed():
        flash("Email и пароль (от 6 символов) обязательны.", "error")
        return redirect(url_for("auth_page"))

    if not _captcha_passed():
        flash("Неверный ответ на капчу. Попробуйте ещё раз.", "error")
        return redirect(url_for("auth_page"))

    email = (request.form.get("email") or "").lower().strip()
    pw = request.form.get("password") or ""
    name = (request.form.get("name") or "").strip() or email.split("@")[0]
    if not email or len(pw) < 6:
        flash("Email и пароль (от 6 символов) обязательны.", "error")
        return redirect(url_for("auth_page"))
    if User.query.filter_by(email=email).first():
        flash("Пользователь с таким email уже есть.", "error")
        return redirect(url_for("auth_page"))

    is_first = User.query.count() == 0

    user = User(
        email=email,
        name=name,
        password_hash=generate_password_hash(pw),
        provider="email",
        is_admin=(is_first or _is_admin_email(email)),
    )
    db.session.add(user)
    db.session.commit()
    login_user(user, remember=True)
    flash("Аккаунт создан.", "ok")
    return redirect(session.pop("post_login_next", None) or url_for("index"))


@app.route("/auth/<provider>")
def oauth_login(provider):
    if not has_provider(provider):
        flash(f"Провайдер {provider} не настроен (нет ключей в .env).", "error")
        return redirect(url_for("auth_page"))
    client = oauth.create_client(provider)
    return client.authorize_redirect(_redirect_uri(provider))


@app.route("/auth/<provider>/callback")
def oauth_callback(provider):
    if not has_provider(provider):
        return redirect(url_for("auth_page"))
    client = oauth.create_client(provider)
    token = client.authorize_access_token()

    if provider == "google":
        info = token.get("userinfo") or client.userinfo()
        return _finalize_login(
            email=info.get("email"),
            name=info.get("name"),
            avatar=info.get("picture"),
            provider="google",
        )

    if provider == "discord":
        resp = client.get("users/@me")
        info = resp.json()
        avatar = None
        if info.get("avatar"):
            avatar = f"https://cdn.discordapp.com/avatars/{info['id']}/{info['avatar']}.png"
        return _finalize_login(
            email=info.get("email"),
            name=info.get("global_name") or info.get("username"),
            avatar=avatar,
            provider="discord",
        )

    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    logout_user()
    session.pop("admin_gate_ok", None)
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Admin panel
# ---------------------------------------------------------------------------
@app.route("/admin")
@admin_required
def admin_home():
    return render_template(
        "admin/dashboard.html",
        stats={
            "users": User.query.count(),
            "services": Service.query.count(),
            "reviews": Review.query.count(),
            "news": NewsItem.query.count(),
            "partners": Partner.query.count(),
            "keys_unused": RedeemCode.query.filter_by(is_used=False).count(),
            "builds": Build.query.count(),
            "purchases": Purchase.query.count(),
        },
    )


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    keys = [
        "brand_name", "brand_tagline", "brand_logo",
        "hero_title", "hero_subtitle", "hero_cta_text",
        "about_text", "background_color", "background_image", "accent_color",
        "link_discord", "link_telegram", "link_funpay", "link_support",
        "maintenance_text", "particle_effect",
    ]
    if request.method == "POST":
        for k in keys:
            set_setting(k, request.form.get(k, "").strip())

        logo_url = _save_upload(request.files.get("brand_logo_upload"))
        if logo_url:
            set_setting("brand_logo", logo_url)
        elif request.form.get("brand_logo_clear"):
            set_setting("brand_logo", "")

        bg_url = _save_upload(request.files.get("background_image_upload"))
        if bg_url:
            set_setting("background_image", bg_url)
        elif request.form.get("background_image_clear"):
            set_setting("background_image", "")

        set_setting("maintenance", "1" if request.form.get("maintenance") else "0")
        db.session.commit()
        flash("Настройки сохранены.", "ok")
        return redirect(url_for("admin_settings"))

    values = {k: get_setting(k, "") for k in keys}
    values["maintenance"] = get_setting("maintenance", "0") == "1"
    return render_template("admin/settings.html", values=values)


# --- ключи пополнения баланса ---
def _gen_redeem_code() -> str:
    alphabet = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4)]
    return "-".join(parts)


@app.route("/admin/keys", methods=["GET", "POST"])
@admin_required
def admin_keys():
    if request.method == "POST":
        try:
            amount = int(request.form.get("amount") or 0)
        except ValueError:
            amount = 0
        try:
            count = int(request.form.get("count") or 1)
        except ValueError:
            count = 1
        count = max(1, min(50, count))

        if amount <= 0:
            flash("Укажите сумму ключа больше нуля.", "error")
        else:
            new_codes = []
            for _ in range(count):
                code = _gen_redeem_code()
                while RedeemCode.query.filter_by(code=code).first():
                    code = _gen_redeem_code()
                db.session.add(RedeemCode(code=code, amount=amount, created_by_id=current_user.id))
                new_codes.append(code)
            db.session.commit()
            flash(f"Сгенерировано ключей: {count} · по {amount} ₽ каждый.", "ok")
        return redirect(url_for("admin_keys"))

    items = RedeemCode.query.order_by(RedeemCode.created_at.desc()).all()
    stats = {
        "total": len(items),
        "unused": sum(1 for r in items if not r.is_used),
        "used": sum(1 for r in items if r.is_used),
    }
    return render_template("admin/keys.html", items=items, stats=stats)


@app.route("/admin/keys/<int:kid>/delete", methods=["POST"])
@admin_required
def admin_keys_delete(kid):
    rc = RedeemCode.query.get_or_404(kid)
    if rc.is_used:
        flash("Нельзя удалить уже активированный ключ.", "error")
    else:
        db.session.delete(rc)
        db.session.commit()
    return redirect(url_for("admin_keys"))


# --- services ---
@app.route("/admin/services", methods=["GET", "POST"])
@admin_required
def admin_services():
    if request.method == "POST":
        s = Service(
            title=request.form["title"],
            price=request.form.get("price", ""),
            description=request.form.get("description", ""),
            order=int(request.form.get("order") or 0),
        )
        db.session.add(s)
        db.session.commit()
        flash("Услуга добавлена.", "ok")
        return redirect(url_for("admin_services"))
    items = Service.query.order_by(Service.order, Service.id).all()
    return render_template("admin/services.html", items=items)


@app.route("/admin/services/<int:sid>/update", methods=["POST"])
@admin_required
def admin_services_update(sid):
    s = Service.query.get_or_404(sid)
    s.title = request.form["title"]
    s.price = request.form.get("price", "")
    s.description = request.form.get("description", "")
    s.order = int(request.form.get("order") or 0)
    db.session.commit()
    flash("Сохранено.", "ok")
    return redirect(url_for("admin_services"))


@app.route("/admin/services/<int:sid>/delete", methods=["POST"])
@admin_required
def admin_services_delete(sid):
    db.session.delete(Service.query.get_or_404(sid))
    db.session.commit()
    return redirect(url_for("admin_services"))


# --- сборки (Build) ---
@app.route("/admin/builds", methods=["GET", "POST"])
@admin_required
def admin_builds():
    if request.method == "POST":
        try:
            price = int(request.form.get("price") or 0)
        except ValueError:
            price = 0
        b = Build(
            title=request.form["title"].strip(),
            tier_label=request.form.get("tier_label", "").strip(),
            price=price,
            description=request.form.get("description", "").strip(),
            download_url=request.form.get("download_url", "").strip(),
            order=int(request.form.get("order") or 0),
            is_active=True,
        )
        db.session.add(b)
        db.session.commit()
        flash(f"Сборка «{b.title}» добавлена.", "ok")
        return redirect(url_for("admin_builds"))

    items = Build.query.order_by(Build.order, Build.id).all()
    purchases_count = {
        b.id: Purchase.query.filter_by(build_id=b.id).count() for b in items
    }
    return render_template("admin/builds.html", items=items, purchases_count=purchases_count)


@app.route("/admin/builds/<int:bid>/update", methods=["POST"])
@admin_required
def admin_builds_update(bid):
    b = Build.query.get_or_404(bid)
    try:
        b.price = int(request.form.get("price") or 0)
    except ValueError:
        b.price = 0
    b.title = request.form.get("title", b.title).strip()
    b.tier_label = request.form.get("tier_label", "").strip()
    b.description = request.form.get("description", "").strip()
    b.download_url = request.form.get("download_url", "").strip()
    b.order = int(request.form.get("order") or 0)
    b.is_active = bool(request.form.get("is_active"))
    db.session.commit()
    flash("Сборка сохранена.", "ok")
    return redirect(url_for("admin_builds"))


@app.route("/admin/builds/<int:bid>/delete", methods=["POST"])
@admin_required
def admin_builds_delete(bid):
    b = Build.query.get_or_404(bid)
    if Purchase.query.filter_by(build_id=b.id).count() > 0:
        flash("Нельзя удалить сборку, у которой уже есть покупки. Можно деактивировать её.", "error")
        return redirect(url_for("admin_builds"))
    db.session.delete(b)
    db.session.commit()
    flash("Сборка удалена.", "ok")
    return redirect(url_for("admin_builds"))


# --- reviews ---
@app.route("/admin/reviews", methods=["GET", "POST"])
@admin_required
def admin_reviews():
    if request.method == "POST":
        db.session.add(Review(
            category=request.form.get("category") or REVIEW_CATEGORIES[0],
            author=request.form.get("author", ""),
            text=request.form["text"],
            rating=int(request.form.get("rating") or 5),
        ))
        db.session.commit()
        return redirect(url_for("admin_reviews"))
    items = Review.query.order_by(Review.created_at.desc()).all()
    return render_template("admin/reviews.html", items=items, categories=REVIEW_CATEGORIES)


@app.route("/admin/reviews/<int:rid>/delete", methods=["POST"])
@admin_required
def admin_reviews_delete(rid):
    db.session.delete(Review.query.get_or_404(rid))
    db.session.commit()
    return redirect(url_for("admin_reviews"))


# --- news ---
@app.route("/admin/news", methods=["GET", "POST"])
@admin_required
def admin_news():
    if request.method == "POST":
        db.session.add(NewsItem(
            title=request.form["title"],
            body=request.form.get("body", ""),
        ))
        db.session.commit()
        return redirect(url_for("admin_news"))
    items = NewsItem.query.order_by(NewsItem.created_at.desc()).all()
    return render_template("admin/news.html", items=items)


@app.route("/admin/news/<int:nid>/delete", methods=["POST"])
@admin_required
def admin_news_delete(nid):
    db.session.delete(NewsItem.query.get_or_404(nid))
    db.session.commit()
    return redirect(url_for("admin_news"))


# --- partners ---
@app.route("/admin/partners", methods=["GET", "POST"])
@admin_required
def admin_partners():
    if request.method == "POST":
        db.session.add(Partner(
            name=request.form["name"],
            url=request.form.get("url", ""),
            logo_url=request.form.get("logo_url", ""),
        ))
        db.session.commit()
        return redirect(url_for("admin_partners"))
    items = Partner.query.order_by(Partner.id).all()
    return render_template("admin/partners.html", items=items)


@app.route("/admin/partners/<int:pid>/delete", methods=["POST"])
@admin_required
def admin_partners_delete(pid):
    db.session.delete(Partner.query.get_or_404(pid))
    db.session.commit()
    return redirect(url_for("admin_partners"))


# --- admins ---
@app.route("/admin/admins", methods=["GET", "POST"])
@admin_required
def admin_admins():
    if request.method == "POST":
        email = (request.form.get("email") or "").lower().strip()
        action = request.form.get("action", "grant")
        u = User.query.filter_by(email=email).first()
        if not u:
            u = User(email=email, name=email.split("@")[0], provider="pending")
            db.session.add(u)
        # Нельзя снять права с хардкод-админов
        if action != "grant" and _is_admin_email(email):
            flash(f"Нельзя снять права с системного администратора: {email}", "error")
            return redirect(url_for("admin_admins"))
        u.is_admin = (action == "grant")
        db.session.commit()
        flash(f"{'Назначен' if u.is_admin else 'Снят'} админ: {email}", "ok")
        return redirect(url_for("admin_admins"))
    users = User.query.order_by(User.is_admin.desc(), User.created_at.desc()).all()
    return render_template("admin/admins.html", users=users)


# ---------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------
def _migrate_review_table():
    """Добавляет новые колонки в уже существующую таблицу review (без Alembic)."""
    insp = inspect(db.engine)
    if "review" not in insp.get_table_names():
        return
    cols = {c["name"] for c in insp.get_columns("review")}
    with db.engine.begin() as conn:
        if "category" not in cols:
            conn.execute(sa_text(
                f"ALTER TABLE review ADD COLUMN category VARCHAR(50) DEFAULT '{REVIEW_CATEGORIES[0]}'"
            ))
        if "user_id" not in cols:
            conn.execute(sa_text("ALTER TABLE review ADD COLUMN user_id INTEGER"))


def _migrate_user_table():
    """Добавляет колонку balance в уже существующую таблицу user (без Alembic)."""
    insp = inspect(db.engine)
    if "user" not in insp.get_table_names():
        return
    cols = {c["name"] for c in insp.get_columns("user")}
    with db.engine.begin() as conn:
        if "balance" not in cols:
            conn.execute(sa_text("ALTER TABLE user ADD COLUMN balance INTEGER DEFAULT 0"))


def _ensure_hardcoded_admins():
    """Гарантирует, что все хардкод-админы имеют is_admin=True в БД."""
    for email in HARDCODED_ADMINS:
        u = User.query.filter_by(email=email).first()
        if u and not u.is_admin:
            u.is_admin = True


def seed():
    """
    Создаёт таблицы и заполняет стартовые данные.

    ВАЖНО: gunicorn запускает несколько воркеров (см. Procfile: -w 2), и каждый
    воркер импортирует этот модуль отдельно — то есть seed() реально вызывается
    несколько раз почти одновременно при старте. Если все воркеры одновременно
    выполнят db.create_all() на PostgreSQL, возможна гонка на системном
    каталоге (UniqueViolation на pg_type/pg_class).

    Решение — PostgreSQL advisory lock: только один воркер реально выполняет
    создание таблиц и засев данных, остальные дожидаются его и идут дальше
    без повторной работы и без гонки. На SQLite advisory lock не существует
    и не нужен (там нет параллельных подключений в той же степени), поэтому
    в этом случае сразу выполняем обычную инициализацию.
    """
    is_postgres = app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgresql")

    with app.app_context():
        lock_acquired = True
        if is_postgres:
            # Произвольное фиксированное число — просто "имя" замка, общее
            # для всех воркеров этого приложения.
            LOCK_KEY = 727182
            try:
                db.session.execute(sa_text("SELECT pg_advisory_lock(:k)"), {"k": LOCK_KEY})
            except Exception as e:
                app.logger.warning("Не удалось взять advisory lock, продолжаем без него: %s", e)
                lock_acquired = False

        try:
            _run_seed_steps()
        finally:
            if is_postgres and lock_acquired:
                try:
                    db.session.execute(sa_text("SELECT pg_advisory_unlock(:k)"), {"k": 727182})
                    db.session.commit()
                except Exception:
                    db.session.rollback()


def _run_seed_steps():
    """Фактическое создание таблиц и засев стартовых данных (вызывается из seed())."""
    try:
        db.create_all()
    except Exception as e:  # подстраховка на случай гонки, даже если lock не сработал
        db.session.rollback()
        app.logger.warning("db.create_all() пропущен (вероятно гонка воркеров): %s", e)

    try:
        _migrate_review_table()
        _migrate_user_table()
    except Exception as e:
        db.session.rollback()
        app.logger.warning("Миграция колонок пропущена (вероятно гонка воркеров): %s", e)

    try:
        _ensure_hardcoded_admins()

        # defaults
        for k, v in DEFAULT_SETTINGS.items():
            if Setting.query.get(k) is None:
                db.session.add(Setting(key=k, value=v))

        if Service.query.count() == 0:
            for i, (t, p, d) in enumerate([
                ("RW Default", "от 500₽", "Стандартный пакет настройки сервера."),
                ("RW Full", "от 1500₽", "Полная сборка с плагинами и кастомом."),
                ("RW Business", "от 5000₽", "Бизнес-пакет: поддержка 24/7, индивидуальные решения."),
            ]):
                db.session.add(Service(title=t, price=p, description=d, order=i))

        if Partner.query.count() == 0:
            db.session.add(Partner(
                name="FunPay",
                url="https://funpay.com/users/17053232/",
                logo_url="",
            ))

        if Build.query.count() == 0:
            for i, (title, tier, price) in enumerate([
                ("RW Default", "TIER 01", 249),
                ("RW Full", "TIER 02", 470),
                ("RW Premium", "TIER 03", 700),
            ]):
                db.session.add(Build(
                    title=title, tier_label=tier, price=price,
                    description="", download_url="", order=i, is_active=True,
                ))

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.warning("Seed стартовых данных пропущен (вероятно гонка воркеров): %s", e)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    seed()
    app.run(host="0.0.0.0", port=5000, debug=os.getenv("FLASK_DEBUG") == "1")
else:
    seed()
