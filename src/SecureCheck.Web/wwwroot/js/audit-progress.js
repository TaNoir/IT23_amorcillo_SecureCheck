// Polls /Audits/Progress/{runId}?handler=Status every 2 seconds until the AuditRun finishes.
// Uses DOM node creation and textContent (never innerHTML with dynamic data).
(function () {
    const root = document.getElementById('auditProgressRoot');
    if (!root) {
        return;
    }

    const statusUrl = root.getAttribute('data-status-url');
    if (!statusUrl) {
        return;
    }

    if (root.getAttribute('data-is-finished') === 'true') {
        return;
    }

    const POLL_INTERVAL_MS = 2000;
    let pollTimerId = null;
    let stopped = false;

    const runStatusBadge = document.getElementById('runStatusBadge');
    const runProgressCount = document.getElementById('runProgressCount');
    const runProgressPercent = document.getElementById('runProgressPercent');
    const runProgressBar = document.getElementById('runProgressBar');
    const runStartedAt = document.getElementById('runStartedAt');
    const runFinishedAt = document.getElementById('runFinishedAt');
    const pollingIndicator = document.getElementById('pollingIndicator');
    const viewResultsBtn = document.getElementById('viewResultsBtn');
    const tableBody = document.getElementById('progressTableBody');

    function createBadge(badgeClass, text, includeSpinner) {
        const span = document.createElement('span');
        span.className = 'badge ' + badgeClass;

        if (includeSpinner) {
            const spinner = document.createElement('span');
            spinner.className = 'spinner-border spinner-border-sm me-1';
            spinner.setAttribute('role', 'status');
            spinner.setAttribute('aria-hidden', 'true');
            span.appendChild(spinner);
        }

        const label = document.createElement('span');
        label.textContent = text;
        span.appendChild(label);
        return span;
    }

    function createMutedDash() {
        const dash = document.createElement('span');
        dash.className = 'text-muted';
        dash.textContent = '—';
        return dash;
    }

    function replaceChildren(element, nodes) {
        if (!element) {
            return;
        }
        element.textContent = '';
        nodes.forEach(function (node) {
            element.appendChild(node);
        });
    }

    function updateRunSummary(data) {
        if (runStatusBadge) {
            runStatusBadge.className = 'badge ' + (data.statusBadgeClass || 'status-error') + ' fs-6';
            runStatusBadge.textContent = '';

            if (!data.isFinished) {
                const spinner = document.createElement('span');
                spinner.className = 'spinner-border spinner-border-sm me-1';
                spinner.setAttribute('role', 'status');
                spinner.setAttribute('aria-hidden', 'true');
                runStatusBadge.appendChild(spinner);
            }

            const textNode = document.createElement('span');
            textNode.textContent = data.statusDisplay || data.status || '';
            runStatusBadge.appendChild(textNode);
        }

        if (runProgressCount) {
            runProgressCount.textContent = data.completedComputers + ' / ' + data.totalComputers;
        }

        const pct = typeof data.percentComplete === 'number' ? data.percentComplete : 0;

        if (runProgressPercent) {
            runProgressPercent.textContent = pct + '%';
        }

        if (runProgressBar) {
            runProgressBar.style.width = pct + '%';
            runProgressBar.setAttribute('aria-valuenow', String(pct));
            runProgressBar.textContent = pct + '%';

            if (!data.isFinished) {
                runProgressBar.className = 'progress-bar progress-bar-striped progress-bar-animated';
            } else if (data.status === 'CompletedWithErrors') {
                runProgressBar.className = 'progress-bar bg-warning text-dark';
            } else {
                runProgressBar.className = 'progress-bar bg-success';
            }
        }

        if (runStartedAt) {
            runStartedAt.textContent = data.startedAtLocal || 'Queued...';
        }

        if (runFinishedAt) {
            runFinishedAt.textContent = data.finishedAtLocal || 'In progress...';
        }

        if (data.isFinished) {
            root.setAttribute('data-is-finished', 'true');
            if (pollingIndicator) {
                pollingIndicator.classList.add('d-none');
            }
            if (viewResultsBtn) {
                viewResultsBtn.classList.remove('d-none');
            }
        }
    }

    function updateComputerRows(computers) {
        if (!tableBody || !Array.isArray(computers)) {
            return;
        }

        computers.forEach(function (item) {
            const row = tableBody.querySelector('tr[data-computer-audit-id="' + item.computerAuditId + '"]');
            if (!row) {
                return;
            }

            const statusCell = row.querySelector('[data-role="status"]');
            replaceChildren(statusCell, [
                createBadge(item.statusBadgeClass || 'status-error', item.statusDisplay || item.status || '', Boolean(item.isRunning))
            ]);

            const scoreCell = row.querySelector('[data-role="score"]');
            if (item.hasCounts) {
                if (typeof item.score === 'number') {
                    const scoreNum = document.createElement('span');
                    scoreNum.className = 'fw-bold ' + (item.scoreTextClass || '') + ' me-1';
                    scoreNum.textContent = String(item.score);

                    const scoreBadge = createBadge(item.scoreBadgeClass || 'status-error', item.scoreLabel || '', false);
                    replaceChildren(scoreCell, [scoreNum, scoreBadge]);
                } else {
                    replaceChildren(scoreCell, [createBadge('status-error', 'N/A', false)]);
                }
            } else {
                replaceChildren(scoreCell, [createMutedDash()]);
            }

            const riskCell = row.querySelector('[data-role="risk"]');
            if (item.overallRiskBadgeClass) {
                replaceChildren(riskCell, [createBadge(item.overallRiskBadgeClass, item.overallRiskDisplay || '', false)]);
            } else {
                replaceChildren(riskCell, [createMutedDash()]);
            }

            const countsCell = row.querySelector('[data-role="counts"]');
            if (item.hasCounts) {
                const wrap = document.createElement('div');
                wrap.className = 'd-flex flex-wrap gap-1';
                wrap.appendChild(createBadge('risk-low', item.passedCount + ' Pass', false));
                wrap.appendChild(createBadge('risk-critical', item.failedCount + ' Fail', false));
                if (item.errorCount > 0) {
                    wrap.appendChild(createBadge('status-error', item.errorCount + ' Error', false));
                }
                replaceChildren(countsCell, [wrap]);
            } else {
                replaceChildren(countsCell, [createMutedDash()]);
            }

            const detailsCell = row.querySelector('[data-role="details"]');
            const detailSpan = document.createElement('span');
            if (item.errorMessage) {
                detailSpan.className = 'text-sc-red';
                detailSpan.textContent = item.errorMessage;
            } else if (item.hasCounts && item.osCaption) {
                detailSpan.className = 'text-muted';
                detailSpan.textContent = item.osCaption;
            } else if (item.isRunning) {
                detailSpan.className = 'text-muted';
                detailSpan.textContent = 'Collecting security settings...';
            } else if (item.status === 'Pending') {
                detailSpan.className = 'text-muted';
                detailSpan.textContent = 'Waiting in queue...';
            } else {
                detailSpan.className = 'text-muted';
                detailSpan.textContent = '—';
            }
            replaceChildren(detailsCell, [detailSpan]);
        });
    }

    async function pollOnce() {
        if (stopped) {
            return;
        }

        try {
            const response = await fetch(statusUrl, {
                method: 'GET',
                headers: { 'Accept': 'application/json' },
                cache: 'no-store'
            });

            if (response.ok) {
                const data = await response.json();
                updateRunSummary(data);
                updateComputerRows(data.computers);

                if (data.isFinished) {
                    stopped = true;
                    return;
                }
            }
        } catch (_err) {
            // Transient network error; retry on the next 2-second tick.
        }

        if (!stopped) {
            pollTimerId = window.setTimeout(pollOnce, POLL_INTERVAL_MS);
        }
    }

    pollTimerId = window.setTimeout(pollOnce, POLL_INTERVAL_MS);

    window.addEventListener('pagehide', function () {
        stopped = true;
        if (pollTimerId !== null) {
            window.clearTimeout(pollTimerId);
        }
    });
})();

