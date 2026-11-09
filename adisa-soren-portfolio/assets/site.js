/* the menu button on a tablet or phone: opens the sheet system.css draws for .nav.is-open, closes on any tap in it */
(function () {
  var nav = document.querySelector('.nav'), btn = nav && nav.querySelector('.nav__toggle');
  if (!btn) return;
  function set(open) { nav.classList.toggle('is-open', open); btn.setAttribute('aria-expanded', String(open)); }
  btn.addEventListener('click', function () { set(!nav.classList.contains('is-open')); });
  nav.addEventListener('click', function (e) { if (e.target.closest('.nav__links a, .nav__actions a')) set(false); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') set(false); });
})();
