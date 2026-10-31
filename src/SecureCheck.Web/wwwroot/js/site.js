// SecureCheck site-wide scripts.

// Any button/link with data-confirm="message" asks before continuing.
// The message is read as plain text (never executed), so names containing quotes are safe.
document.addEventListener('click', function (event) {
    const trigger = event.target.closest('[data-confirm]');
    if (trigger && !window.confirm(trigger.getAttribute('data-confirm'))) {
        event.preventDefault();
        return;
    }

    const copyBtn = event.target.closest('[data-copy-target]');
    if (copyBtn && navigator.clipboard) {
        const selector = copyBtn.getAttribute('data-copy-target');
        const target = selector ? document.querySelector(selector) : null;
        if (target) {
            navigator.clipboard.writeText(target.textContent || '').then(function () {
                const originalHtml = copyBtn.innerHTML;
                copyBtn.textContent = 'Copied!';
                setTimeout(function () {
                    copyBtn.innerHTML = originalHtml;
                }, 1500);
            });
        }
    }
});

// Disables submit buttons carrying data-loading-text="..." while a long operation is running.
document.addEventListener('submit', function (event) {
    if (event.defaultPrevented) {
        return;
    }

    const submitter = event.submitter;
    if (!submitter || !submitter.hasAttribute('data-loading-text')) {
        return;
    }

    const loadingText = submitter.getAttribute('data-loading-text') || 'Working...';
    setTimeout(function () {
        submitter.disabled = true;
        submitter.textContent = '';
        const spinner = document.createElement('span');
        spinner.className = 'spinner-border spinner-border-sm me-1';
        spinner.setAttribute('role', 'status');
        spinner.setAttribute('aria-hidden', 'true');
        submitter.appendChild(spinner);
        submitter.appendChild(document.createTextNode(loadingText));
    }, 0);
});
