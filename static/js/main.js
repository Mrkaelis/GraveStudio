setTimeout(() => {
  document.querySelectorAll('.flash').forEach(el => {
    el.style.opacity = 0;
    el.style.transition = 'opacity .4s';
    setTimeout(() => el.remove(), 400);
  });
}, 3500);

function authTab(which) {
  document.querySelectorAll('.auth-tabs button').forEach(b => b.classList.remove('active'));
  document.querySelector('[data-tab="' + which + '"]').classList.add('active');
  document.getElementById('form-login').style.display    = which === 'login'    ? 'block' : 'none';
  document.getElementById('form-register').style.display = which === 'register' ? 'block' : 'none';
}
