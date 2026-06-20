/* ===========================================================================
   Партиклы — лёгкая canvas-анимация поверх сайта.
   Эффект выбирается в админ-панели (Настройки → Партиклы) и приходит сюда
   через data-effect атрибут канваса (#particles-fx, см. base.html).
   На страницах админ-панели канвас скрыт через CSS (.admin-layout ~ ...),
   поэтому здесь же мы не запускаем анимацию, если канвас не виден —
   это экономит CPU/батарею.
=========================================================================== */
(function () {
  "use strict";

  const canvas = document.getElementById("particles-fx");
  if (!canvas) return;

  const effect = (canvas.dataset.effect || "none").toLowerCase();
  if (effect === "none" || effect === "") return;

  // Уважаем настройку "уменьшить анимацию" в ОС/браузере пользователя.
  if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    return;
  }

  // Канвас скрыт CSS-ом (например, мы в админ-панели) — анимацию не запускаем.
  function isHidden() {
    const cs = window.getComputedStyle(canvas);
    return cs.display === "none" || cs.visibility === "hidden";
  }
  if (isHidden()) return;

  const ctx = canvas.getContext("2d");
  let dpr = Math.min(window.devicePixelRatio || 1, 2);
  let width = 0, height = 0;

  function resize() {
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    canvas.style.width = width + "px";
    canvas.style.height = height + "px";
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  resize();
  window.addEventListener("resize", resize);

  function rand(min, max) { return min + Math.random() * (max - min); }

  // -------------------------------------------------------------------------
  // Пресеты эффектов. Каждый умеет создать частицу и обновить/нарисовать её.
  // -------------------------------------------------------------------------
  const PRESETS = {
    // ❄️ Зима — снег: падает вниз, лёгкое раскачивание влево-вправо.
    winter: {
      count: Math.min(90, Math.floor(width / 14)),
      spawn() {
        return {
          x: rand(0, width),
          y: rand(-height, height),
          r: rand(1.4, 3.6),
          speedY: rand(18, 48),
          sway: rand(8, 28),
          swaySpeed: rand(0.5, 1.4),
          phase: rand(0, Math.PI * 2),
          alpha: rand(0.45, 0.95),
        };
      },
      update(p, dt, t) {
        p.y += p.speedY * dt;
        p.x += Math.sin(t * p.swaySpeed + p.phase) * p.sway * dt;
        if (p.y > height + 10) { p.y = -10; p.x = rand(0, width); }
      },
      draw(p) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255,255,255,${p.alpha})`;
        ctx.fill();
      },
    },

    // 🌸 Весна — лепестки: падают по диагонали, медленно вращаются.
    spring: {
      count: Math.min(55, Math.floor(width / 20)),
      colors: ["#ffd6e8", "#ffc1dd", "#ffe8f1", "#ffb6c9"],
      spawn() {
        return {
          x: rand(0, width),
          y: rand(-height, height),
          size: rand(5, 10),
          speedY: rand(14, 30),
          speedX: rand(6, 18),
          rot: rand(0, Math.PI * 2),
          rotSpeed: rand(-1, 1),
          color: this.colors[Math.floor(Math.random() * this.colors.length)],
          alpha: rand(0.55, 0.9),
        };
      },
      update(p, dt) {
        p.y += p.speedY * dt;
        p.x += p.speedX * dt;
        p.rot += p.rotSpeed * dt;
        if (p.y > height + 20) { p.y = -20; p.x = rand(0, width); }
        if (p.x > width + 20) p.x = -20;
      },
      draw(p) {
        ctx.save();
        ctx.translate(p.x, p.y);
        ctx.rotate(p.rot);
        ctx.globalAlpha = p.alpha;
        ctx.fillStyle = p.color;
        ctx.beginPath();
        ctx.ellipse(0, 0, p.size, p.size * 0.55, 0, 0, Math.PI * 2);
        ctx.fill();
        ctx.restore();
      },
    },

    // ✨ Лето — светлячки: медленно блуждают, мерцают тёплым светом.
    summer: {
      count: Math.min(45, Math.floor(width / 24)),
      spawn() {
        return {
          x: rand(0, width),
          y: rand(0, height),
          r: rand(1.6, 3.2),
          angle: rand(0, Math.PI * 2),
          speed: rand(6, 16),
          turnSpeed: rand(-0.6, 0.6),
          blinkSpeed: rand(0.6, 1.8),
          phase: rand(0, Math.PI * 2),
        };
      },
      update(p, dt, t) {
        p.angle += p.turnSpeed * dt;
        p.x += Math.cos(p.angle) * p.speed * dt;
        p.y += Math.sin(p.angle) * p.speed * dt;
        if (p.x < -10) p.x = width + 10;
        if (p.x > width + 10) p.x = -10;
        if (p.y < -10) p.y = height + 10;
        if (p.y > height + 10) p.y = -10;
        p.alpha = 0.35 + 0.65 * (0.5 + 0.5 * Math.sin(t * p.blinkSpeed + p.phase));
      },
      draw(p) {
        const glow = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.r * 5);
        glow.addColorStop(0, `rgba(255,220,140,${p.alpha})`);
        glow.addColorStop(1, "rgba(255,220,140,0)");
        ctx.fillStyle = glow;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r * 5, 0, Math.PI * 2);
        ctx.fill();
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255,245,210,${Math.min(1, p.alpha + 0.2)})`;
        ctx.fill();
      },
    },

    // 🍂 Осень — листья: падают быстрее снега, с заметным вращением и сносом.
    autumn: {
      count: Math.min(60, Math.floor(width / 18)),
      colors: ["#d97a3f", "#c2632e", "#e0a458", "#8c4a2b"],
      spawn() {
        return {
          x: rand(0, width),
          y: rand(-height, height),
          size: rand(5, 9),
          speedY: rand(28, 58),
          sway: rand(20, 50),
          swaySpeed: rand(0.4, 1.1),
          phase: rand(0, Math.PI * 2),
          rot: rand(0, Math.PI * 2),
          rotSpeed: rand(-2.2, 2.2),
          color: this.colors[Math.floor(Math.random() * this.colors.length)],
          alpha: rand(0.6, 0.95),
        };
      },
      update(p, dt, t) {
        p.y += p.speedY * dt;
        p.x += Math.sin(t * p.swaySpeed + p.phase) * p.sway * dt;
        p.rot += p.rotSpeed * dt;
        if (p.y > height + 20) { p.y = -20; p.x = rand(0, width); }
      },
      draw(p) {
        ctx.save();
        ctx.translate(p.x, p.y);
        ctx.rotate(p.rot);
        ctx.globalAlpha = p.alpha;
        ctx.fillStyle = p.color;
        ctx.beginPath();
        ctx.moveTo(0, -p.size);
        ctx.quadraticCurveTo(p.size, 0, 0, p.size);
        ctx.quadraticCurveTo(-p.size, 0, 0, -p.size);
        ctx.fill();
        ctx.restore();
      },
    },

    // 🔮 Магия — искры: поднимаются вверх, мерцают, угасают.
    magic: {
      count: Math.min(70, Math.floor(width / 16)),
      colors: ["#a855f7", "#7c3aed", "#d8b4fe", "#c084fc"],
      spawn() {
        return {
          x: rand(0, width),
          y: rand(0, height),
          r: rand(1, 2.6),
          speedY: rand(10, 26),
          sway: rand(6, 18),
          swaySpeed: rand(0.6, 1.6),
          phase: rand(0, Math.PI * 2),
          blinkSpeed: rand(1, 3),
          color: this.colors[Math.floor(Math.random() * this.colors.length)],
        };
      },
      update(p, dt, t) {
        p.y -= p.speedY * dt;
        p.x += Math.sin(t * p.swaySpeed + p.phase) * p.sway * dt;
        if (p.y < -10) { p.y = height + 10; p.x = rand(0, width); }
        p.alpha = 0.25 + 0.75 * (0.5 + 0.5 * Math.sin(t * p.blinkSpeed + p.phase));
      },
      draw(p) {
        const glow = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.r * 4);
        glow.addColorStop(0, p.color);
        glow.addColorStop(1, "rgba(124,58,237,0)");
        ctx.globalAlpha = p.alpha;
        ctx.fillStyle = glow;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r * 4, 0, Math.PI * 2);
        ctx.fill();
        ctx.globalAlpha = 1;
      },
    },
  };

  const preset = PRESETS[effect];
  if (!preset) return; // неизвестное значение эффекта — ничего не рисуем

  let particles = [];
  function seed() {
    particles = [];
    for (let i = 0; i < preset.count; i++) particles.push(preset.spawn());
  }
  seed();

  // Если на телефоне/слабом устройстве — поубавим частиц, чтоб не лагало.
  if (navigator.hardwareConcurrency && navigator.hardwareConcurrency <= 4) {
    particles = particles.slice(0, Math.ceil(particles.length * 0.6));
  }

  let rafId = null;
  let lastTime = performance.now();
  const start = lastTime;

  function frame(now) {
    const dt = Math.min(0.05, (now - lastTime) / 1000); // сек, защита от скачков
    lastTime = now;
    const t = (now - start) / 1000;

    ctx.clearRect(0, 0, width, height);
    for (const p of particles) {
      preset.update(p, dt, t);
      preset.draw(p);
    }
    rafId = requestAnimationFrame(frame);
  }

  function play() {
    if (rafId === null) {
      lastTime = performance.now();
      rafId = requestAnimationFrame(frame);
    }
  }
  function pause() {
    if (rafId !== null) {
      cancelAnimationFrame(rafId);
      rafId = null;
    }
  }

  // Не тратим CPU, когда вкладка не активна.
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) pause(); else play();
  });

  play();
})();
