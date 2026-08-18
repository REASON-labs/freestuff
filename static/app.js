/* ------------------------------------------------------------------ *
   FreeStuff — small shared behaviours.

   Confirmation prompts:
     Put data-confirm="…" on a <form>. The text is read from the attribute at
     submit time, so user-supplied values (claimant names, item titles) live in
     an HTML attribute and never inside a JavaScript string. Building the
     prompt with inline onsubmit="confirm('…')" let a claimant break out of the
     string with an apostrophe and run script in the admin's browser.
 * ------------------------------------------------------------------ */
(function () {
  'use strict';

  document.addEventListener('submit', function (event) {
    var form = event.target;
    if (!form || form.nodeName !== 'FORM') return;

    var message = form.getAttribute('data-confirm');
    if (!message) return;

    if (!window.confirm(message)) {
      event.preventDefault();
    }
  });
})();
