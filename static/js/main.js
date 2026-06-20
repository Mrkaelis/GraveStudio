setTimeout(() => {
  document.querySelectorAll('.flash').forEach(el => {
    el.style.opacity = 0;
    el.style.transition = 'opacity .4s';
    setTimeout(() => el.remove(), 400);
  });
}, 3500);

function toggleProfileMenu(e) {
  e.stopPropagation();
  const menu = document.getElementById('profile-menu');
  if (!menu) return;
  menu.classList.toggle('open');
}
document.addEventListener('click', (e) => {
  const menu = document.getElementById('profile-menu');
  if (!menu || !menu.classList.contains('open')) return;
  const wrap = menu.closest('.profile-wrap');
  if (wrap && !wrap.contains(e.target)) {
    menu.classList.remove('open');
  }
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    const menu = document.getElementById('profile-menu');
    if (menu) menu.classList.remove('open');
  }
});

function authTab(which) {
  document.querySelectorAll('.auth-tabs button').forEach(b => b.classList.remove('active'));
  document.querySelector('[data-tab="' + which + '"]').classList.add('active');
  document.getElementById('form-login').style.display    = which === 'login'    ? 'block' : 'none';
  document.getElementById('form-register').style.display = which === 'register' ? 'block' : 'none';
}
