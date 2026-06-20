# GraveStudio

Сайт-визитка студии **GraveStudio** на Python (Flask) с:

- авторизацией через **Google** и **Discord** (а также email/пароль),
- ролевой моделью (админ / пользователь),
- админ-панелью по адресу **`/admin`**, где редактируется **всё**: название бренда, слоган, ссылки Discord / Telegram / FunPay / Support, услуги, отзывы, новости, партнёры, блок «О нас», тех.работы.

Первые админы по умолчанию: `kvaka3927@gmail.com`, `dimacontrol2223@gmail.com` — как только они войдут (любым способом), они автоматически получат роль `admin`.

## Запуск локально

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # заполните ключи
python app.py
```

Сайт: <http://127.0.0.1:5000>
Админка: <http://127.0.0.1:5000/admin>

## OAuth — где взять ключи

### Google
1. <https://console.cloud.google.com/apis/credentials> → **Create credentials** → **OAuth client ID** → Web application.
2. Authorized redirect URI: `http://127.0.0.1:5000/auth/google/callback`
   (на проде: `https://ВАШ_ДОМЕН/auth/google/callback`).
3. Скопируйте Client ID / Secret в `.env`.

### Discord
1. <https://discord.com/developers/applications> → **New Application** → OAuth2.
2. Redirects: `http://127.0.0.1:5000/auth/discord/callback`.
3. Scopes: `identify email`.
4. Client ID / Secret → в `.env`.

Если ключи не заполнены — соответствующая кнопка просто скрыта, остаётся email/пароль.

## Продакшен

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

И поставьте `OAUTH_REDIRECT_BASE=https://yourdomain.com` в `.env`, а в Google/Discord консолях — добавьте соответствующий callback.

## Что в админке

- Бренд: название, слоган, логотип (URL).
- Социальные ссылки: Discord, Telegram, FunPay, Tех. поддержка (любые URL, кнопки в шапке/футере обновляются мгновенно).
- Услуги (RW Default / Full / Business и любые свои) — добавить / удалить / изменить цену и описание.
- Отзывы.
- Новости.
- Партнёры.
- Блок «О нас».
- Тех.работы (вкл/выкл — сайт переходит в режим заглушки для всех, кроме админов).
- Управление админами: назначить / снять админа по email.
