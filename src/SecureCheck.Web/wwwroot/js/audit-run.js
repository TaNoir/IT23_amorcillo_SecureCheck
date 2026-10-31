// Client-side "Select all" checkbox and live selection counter for /Audits/Run.
(function () {
    const selectAll = document.getElementById('selectAllComputers');
    const countBadge = document.getElementById('selectedCountBadge');
    const checkboxes = Array.from(document.querySelectorAll('.js-computer-checkbox'));

    if (!selectAll || checkboxes.length === 0) {
        return;
    }

    function syncState() {
        const checkedCount = checkboxes.filter(function (cb) { return cb.checked; }).length;
        selectAll.checked = checkedCount === checkboxes.length;
        selectAll.indeterminate = checkedCount > 0 && checkedCount < checkboxes.length;

        if (countBadge) {
            countBadge.textContent = checkedCount + ' selected';
        }
    }

    selectAll.addEventListener('change', function () {
        const shouldCheck = selectAll.checked;
        checkboxes.forEach(function (cb) {
            cb.checked = shouldCheck;
        });
        syncState();
    });

    checkboxes.forEach(function (cb) {
        cb.addEventListener('change', syncState);
    });

    syncState();
})();

