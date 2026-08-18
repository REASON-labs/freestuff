/* ------------------------------------------------------------------ *
   FreeStuff — theme toggle.

   Three states, cycled in this order:  system → light → dark → system

   "system" stores nothing and removes the data-theme attribute, so the
   prefers-color-scheme block in style.css takes over. "light" and "dark"
   set data-theme explicitly and persist to localStorage.

   The pre-paint script in base.html applies the stored choice before first
   paint; this file only handles the button, which stays hidden without JS.
 * ------------------------------------------------------------------ */
(function () {
  'use strict';

  var KEY = 'freestuff-theme';
  var STATES = ['system', 'light', 'dark'];
  var LABELS = {
    system: { icon: '🖥️', text: 'System' },
    light:  { icon: '☀️',       text: 'Light'  },
    dark:   { icon: '🌙',       text: 'Dark'   }
  };

  var root = document.documentElement;
  var btn = document.getElementById('theme-toggle');
  if (!btn) return;

  function read() {
    try {
      var v = localStorage.getItem(KEY);
      return (v === 'light' || v === 'dark') ? v : 'system';
    } catch (e) {
      return 'system';
    }
  }

  function write(state) {
    try {
      if (state === 'system') localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, state);
    } catch (e) { /* storage unavailable — theme still applies for this page */ }
  }

  function apply(state) {
    if (state === 'system') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', state);

    var l = LABELS[state];
    btn.querySelector('.theme-toggle-icon').textContent = l.icon;
    btn.querySelector('.theme-toggle-label').textContent = l.text;
    btn.setAttribute('aria-label', 'Theme: ' + l.text.toLowerCase() + '. Click to change.');
  }

  var current = read();
  apply(current);
  btn.hidden = false;

  btn.addEventListener('click', function () {
    current = STATES[(STATES.indexOf(current) + 1) % STATES.length];
    write(current);
    apply(current);
  });

  // Keep other open tabs in sync when the choice changes elsewhere.
  window.addEventListener('storage', function (e) {
    if (e.key !== KEY) return;
    current = read();
    apply(current);
  });
})();
