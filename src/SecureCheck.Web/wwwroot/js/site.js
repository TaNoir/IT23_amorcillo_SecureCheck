// SecureCheck site-wide scripts.

// Any button/link with data-confirm="message" asks before continuing.
// The message is read as plain text (never executed), so names containing quotes are safe.
document.addEventListener('click', function (event) {
    const trigger = event.target.closest('[data-confirm]');
    if (trigger && !window.confirm(trigger.getAttribute('data-confirm'))) {
        event.preventDefault();
    }
});
