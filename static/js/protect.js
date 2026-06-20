/* ===========================================================================
   Защита от копирования / «дампа» страницы через интерфейс браузера.
   Это мера сдерживания для обычных посетителей: блокирует случайное
   копирование дизайна через ПКМ / выделение / горячие клавиши.
   От целенаправленного скачивания HTML инструментами вроде curl/wget эта
   защита НЕ спасает (это клиентский JS, такие инструменты его не исполняют) —
   для этого на сервере есть отдельная фильтрация по User-Agent и троттлинг
   запросов (см. app.py: anti_scrape_guard).
=========================================================================== */
(function () {
  "use strict";

  function isFormField(el) {
    if (!el || !el.tagName) return false;
    const tag = el.tagName.toLowerCase();
    return tag === "input" || tag === "textarea" || el.isContentEditable;
  }

  // Блокируем контекстное меню (правый клик) — частый способ открыть
  // "Просмотреть код страницы" или сохранить изображение.
  document.addEventListener("contextmenu", function (e) {
    if (isFormField(e.target)) return;
    e.preventDefault();
  });

  // Блокируем перетаскивание изображений (способ быстро сохранить картинку).
  document.addEventListener("dragstart", function (e) {
    if (e.target && e.target.tagName === "IMG") e.preventDefault();
  });

  // Блокируем копирование текста вне полей ввода.
  document.addEventListener("copy", function (e) {
    if (isFormField(e.target)) return;
    e.preventDefault();
  });

  // Блокируем выделение текста вне полей ввода (доп. к CSS user-select:none).
  document.addEventListener("selectstart", function (e) {
    if (isFormField(e.target)) return;
    e.preventDefault();
  });

  // Блокируем горячие клавиши: просмотр исходного кода, сохранение страницы,
  // открытие DevTools.
  function keyGuard(e) {
    const key = (e.key || "").toLowerCase();
    const code = (e.code || "").toLowerCase();
    const ctrlOrCmd = e.ctrlKey || e.metaKey;

    // Ctrl/Cmd + S — сохранение страницы (HTML/«дамп» сайта).
    // Блокируется ВСЕГДА, независимо от того, что в фокусе (включая поля ввода),
    // чтобы страницу не получилось сохранить, кликнув сначала в текстовое поле.
    if (ctrlOrCmd && (key === "s" || code === "keys")) {
      e.preventDefault();
      e.stopPropagation();
      if (e.stopImmediatePropagation) e.stopImmediatePropagation();
      return false;
    }

    if (e.key === "F12") { e.preventDefault(); return; }                     // DevTools
    if (ctrlOrCmd && key === "u") { e.preventDefault(); return; }            // Просмотр кода
    if (ctrlOrCmd && e.shiftKey && ["i", "j", "c", "k"].includes(key)) {     // DevTools панели
      e.preventDefault();
    }
  }

  // Слушаем на фазе "capture" (true) и сразу на document и window,
  // чтобы перехватить нажатие раньше любого другого обработчика
  // и до того, как браузер откроет системный диалог "Сохранить как".
  document.addEventListener("keydown", keyGuard, true);
  window.addEventListener("keydown", keyGuard, true);

  // Доп. страховка: блокируем и на keyup, на случай если какой-то браузер
  // триггерит сохранение по этому событию.
  document.addEventListener("keyup", function (e) {
    const ctrlOrCmd = e.ctrlKey || e.metaKey;
    if (ctrlOrCmd && (e.key || "").toLowerCase() === "s") {
      e.preventDefault();
    }
  }, true);

  // Предупреждение в консоли — классический приём против self-XSS,
  // одновременно сообщает о защите авторских прав.
  console.log(
    "%cСтоп!",
    "color:#ef4444; font-size:42px; font-weight:900;"
  );
  console.log(
    "%cЭто консоль браузера для разработчиков. Вставка сюда чужого кода может " +
    "дать злоумышленникам доступ к вашему аккаунту. Дизайн и код этого сайта " +
    "защищены авторским правом — копирование без разрешения запрещено.",
    "font-size:14px;"
  );

  // Лёгкое обнаружение открытых DevTools (работает для «пристыкованной» панели).
  // Ничего не блокирует — только информирует через консоль.
  let warned = false;
  setInterval(function () {
    const threshold = 160;
    const open =
      window.outerWidth - window.innerWidth > threshold ||
      window.outerHeight - window.innerHeight > threshold;
    if (open && !warned) {
      warned = true;
      console.log("%cОбнаружены открытые инструменты разработчика.", "color:#f59e0b;");
    } else if (!open) {
      warned = false;
    }
  }, 1500);
})();
