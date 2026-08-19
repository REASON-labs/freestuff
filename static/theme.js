/* ------------------------------------------------------------------ *
   FreeStuff — theme toggle.

   Two states, matching RentStuff:

     no stored choice  →  follow the system preference (light if it has none)
     click             →  pin the opposite of what you're currently seeing

   There is no explicit "system" position in the cycle. The previous
   three-state version needed a text label to be usable — with icons alone,
   "system" and whichever theme it currently resolves to look identical, so
   the button couldn't tell you what it would do. Following the system until
   you disagree with it, then honouring that, is the same behaviour with one
   less thing to explain.

   The icon shows the *destination*, not the current state: a moon means
   "click for dark". That matches RentStuff and is the common convention.

   The pre-paint script in base.html applies a stored choice before first
   paint; this file only handles the button, which stays hidden without JS
   (in which case the CSS falls back to the system preference on its own).
 * ------------------------------------------------------------------ */
(function () {
  'use strict';

  var KEY = 'freestuff-theme';

  // Inline SVG rather than emoji: these inherit currentColor, so they pick up
  // the header's link colour in both themes and stay legible. Emoji render at
  // the mercy of the platform font and ignore colour entirely.
  var SUN = '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" ' +
    'stroke="currentColor" stroke-width="2" stroke-linecap="round" ' +
    'stroke-linejoin="round" aria-hidden="true" focusable="false">' +
    '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4' +
    'M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';

  var MOON = '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" ' +
    'stroke="currentColor" stroke-width="2" stroke-linecap="round" ' +
    'stroke-linejoin="round" aria-hidden="true" focusable="false">' +
    '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';

  var root = document.documentElement;
  var btn = document.getElementById('theme-toggle');
  if (!btn) return;

  var mq = window.matchMedia('(prefers-color-scheme: dark)');

  function stored() {
    try {
      var v = localStorage.getItem(KEY);
      return (v === 'light' || v === 'dark') ? v : null;
    } catch (e) {
      return null;   // private mode / storage disabled
    }
  }

  /* What the visitor is actually looking at right now — the stored choice if
     there is one, otherwise whatever the system says, defaulting to light. */
  function effective() {
    return stored() || (mq.matches ? 'dark' : 'light');
  }

  function render() {
    var dark = effective() === 'dark';
    btn.innerHTML = dark ? SUN : MOON;
    btn.setAttribute('aria-label',
      dark ? 'Switch to light theme' : 'Switch to dark theme');
    btn.setAttribute('title', dark ? 'Light mode' : 'Dark mode');
  }

  function apply() {
    var choice = stored();
    // Absent attribute is meaningful: it hands control back to the
    // prefers-color-scheme block in style.css.
    if (choice) root.setAttribute('data-theme', choice);
    else root.removeAttribute('data-theme');
    render();
  }

  apply();
  btn.hidden = false;

  btn.addEventListener('click', function () {
    var next = effective() === 'dark' ? 'light' : 'dark';
    try {
      localStorage.setItem(KEY, next);
    } catch (e) { /* storage unavailable — still themes this page */ }
    root.setAttribute('data-theme', next);
    render();
  });

  // Keep other open tabs in sync when the choice changes elsewhere.
  window.addEventListener('storage', function (e) {
    if (e.key === KEY) apply();
  });

  // Someone on the system default who flips their OS theme should follow it
  // live, without a reload. Ignored once they've pinned a choice of their own.
  mq.addEventListener('change', function () {
    if (!stored()) render();
  });
})();
