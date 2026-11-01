// Chart.js 4.4 initializers for Dashboard (risk doughnut + failed category bars)
// and Computer History (score over time line chart).
// Reads JSON strictly from HTML data-chart attributes; never uses inline scripts or innerHTML.
(function () {
    if (typeof window.Chart === 'undefined') {
        return;
    }

    function readChartPayload(canvas) {
        if (!canvas) {
            return null;
        }
        const raw = canvas.getAttribute('data-chart');
        if (!raw) {
            return null;
        }
        try {
            return JSON.parse(raw);
        } catch (_err) {
            return null;
        }
    }

    // 1. Dashboard: Computers by Overall Risk (Doughnut)
    const riskCanvas = document.getElementById('riskDoughnutChart');
    const riskData = readChartPayload(riskCanvas);
    if (riskCanvas && riskData && Array.isArray(riskData.labels) && Array.isArray(riskData.counts)) {
        new window.Chart(riskCanvas, {
            type: 'doughnut',
            data: {
                labels: riskData.labels,
                datasets: [{
                    data: riskData.counts,
                    backgroundColor: riskData.colors || [
                        '#168653',
                        '#168653',
                        '#E5B72E',
                        '#EC8A3C',
                        '#F45D5B',
                        '#8A94A6'
                    ],
                    borderColor: '#ffffff',
                    borderWidth: 2,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '62%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            boxWidth: 14,
                            padding: 14,
                            usePointStyle: true
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function (ctx) {
                                const value = typeof ctx.parsed === 'number' ? ctx.parsed : 0;
                                const dataset = ctx.dataset && Array.isArray(ctx.dataset.data) ? ctx.dataset.data : [];
                                const total = dataset.reduce(function (acc, n) { return acc + (Number(n) || 0); }, 0);
                                const pct = total > 0 ? Math.round((value * 100) / total) : 0;
                                const unit = value === 1 ? 'computer' : 'computers';
                                return ' ' + ctx.label + ': ' + value + ' ' + unit + ' (' + pct + '%)';
                            }
                        }
                    }
                }
            }
        });
    }

    // 2. Dashboard: Failed Checks per Category (Bar)
    const categoryCanvas = document.getElementById('categoryFailuresChart');
    const categoryData = readChartPayload(categoryCanvas);
    if (categoryCanvas && categoryData && Array.isArray(categoryData.labels) && Array.isArray(categoryData.counts)) {
        new window.Chart(categoryCanvas, {
            type: 'bar',
            data: {
                labels: categoryData.labels,
                datasets: [{
                    label: 'Failed checks',
                    data: categoryData.counts,
                    backgroundColor: '#F45D5B',
                    borderColor: '#F45D5B',
                    borderWidth: 1,
                    borderRadius: 6,
                    maxBarThickness: 48
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    x: {
                        grid: {
                            display: false
                        }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0,
                            stepSize: 1
                        }
                    }
                }
            }
        });
    }

    // 3. Computer History: Security Score over Time (Line)
    const historyCanvas = document.getElementById('computerHistoryChart');
    const historyData = readChartPayload(historyCanvas);
    if (historyCanvas && historyData && Array.isArray(historyData.labels) && Array.isArray(historyData.scores)) {
        const pointColors = Array.isArray(historyData.pointColors) && historyData.pointColors.length === historyData.scores.length
            ? historyData.pointColors
            : '#0A3061';

        new window.Chart(historyCanvas, {
            type: 'line',
            data: {
                labels: historyData.labels,
                datasets: [{
                    label: 'Security Score',
                    data: historyData.scores,
                    borderColor: '#0A3061',
                    backgroundColor: 'rgba(10, 48, 97, 0.08)',
                    borderWidth: 2.5,
                    tension: 0.25,
                    fill: true,
                    pointBackgroundColor: pointColors,
                    pointBorderColor: '#ffffff',
                    pointBorderWidth: 2,
                    pointRadius: 5,
                    pointHoverRadius: 7
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label: function (ctx) {
                                return ' Score: ' + ctx.parsed.y + ' / 100';
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        min: 0,
                        max: 100,
                        ticks: {
                            stepSize: 20
                        }
                    }
                }
            }
        });
    }
})();

