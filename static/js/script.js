// Initialize Chart.js for packet and byte graphs
const packetChartCtx = document.getElementById("packetChart").getContext("2d");
const byteChartCtx = document.getElementById("byteChart").getContext("2d");
const protocolPieChartCtx = document.getElementById("protocolPieChart").getContext("2d");
const packetChart = new Chart(document.getElementById("packetChart").getContext("2d"), {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'Total Packets',
            backgroundColor: 'rgba(75, 192, 192, 0.2)',
            borderColor: 'rgba(75, 192, 192, 1)',
            data: []
        }]
    },
    options: {
        responsive: false,
        maintainAspectRatio: false,
        scales: {
            x: {
                grid: {
                    display: true,
                    color: "#ddd"
                },
                ticks: {
                    maxTicksLimit: 4
                }
            },
            y: {
                grid: {
                    display: true,
                    color: "#ddd"
                },
                ticks: {
                    maxTicksLimit: 4
                }
            }
        },
        plugins: {
            legend: {
                display: false
            }
        }
    }
});

const byteChart = new Chart(document.getElementById("byteChart").getContext("2d"), {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'Total Bytes',
            backgroundColor: 'rgba(255, 159, 64, 0.2)',
            borderColor: 'rgba(255, 159, 64, 1)',
            data: []
        }]
    },
    options: {
        responsive: false,
        maintainAspectRatio: true,
        scales: {
            x: {
                grid: {
                    display: true,
                    color: "#ddd"
                },
                ticks: {
                    maxTicksLimit: 3  // Fewer x-axis ticks
                }
            },
            y: {
                grid: {
                    display: true,
                    color: "#ddd"
                },
                ticks: {
                    maxTicksLimit: 3  // Fewer y-axis ticks
                }
            }
        },
        plugins: {
            legend: {
                display: false  // Hide legend
            }
        }
    }
});

const protocolPieChart = new Chart(document.getElementById("protocolPieChart").getContext("2d"), {
    type: 'pie',
    data: {
        labels: ['TCP Packets', 'UDP Packets'],
        datasets: [{
            label: 'Protocol Distribution',
            backgroundColor: ['rgba(54, 162, 235, 0.7)', 'rgba(255, 99, 132, 0.7)'],
            data: [0, 0]
        }]
    },
    options: {
        responsive: false,
        maintainAspectRatio: true,
        plugins: {
            legend: {
                display: false  // Hide legend to save space
            }
        }
    }
});


function updateCharts(totalPackets, totalBytes) {
    const timeLabel = new Date().toLocaleTimeString();

    if (packetChart.data.labels.length > 10) {
        packetChart.data.labels.shift();
        packetChart.data.datasets[0].data.shift();
        byteChart.data.labels.shift();
        byteChart.data.datasets[0].data.shift();
    }

    packetChart.data.labels.push(timeLabel);
    packetChart.data.datasets[0].data.push(totalPackets);

    byteChart.data.labels.push(timeLabel);
    byteChart.data.datasets[0].data.push(totalBytes);

    packetChart.update();
    byteChart.update();
}

function updatePieChart(tcpPackets, udpPackets) {
    protocolPieChart.data.datasets[0].data = [tcpPackets, udpPackets];
    protocolPieChart.update();
}

function updateMetrics() {
    fetch('/metrics')
        .then(response => response.json())
        .then(data => {
            const totalPackets = data.globalMetrics.totalPackets || 0;
            const totalBytes = data.globalMetrics.totalBytes || 0;
            const tcpPackets = data.globalMetrics.tcpPackets || 0;
            const udpPackets = data.globalMetrics.udpPackets || 0;

            document.getElementById("totalPackets").textContent = totalPackets;
            document.getElementById("totalBytes").textContent = totalBytes;
            document.getElementById("tcpPackets").textContent = tcpPackets;
            document.getElementById("udpPackets").textContent = udpPackets;

            const tableBody = document.getElementById("connectionTable").getElementsByTagName("tbody")[0];
            tableBody.innerHTML = "";

            data.connections.forEach(conn => {
                const row = tableBody.insertRow();
                row.insertCell(0).textContent = conn.connection;
                row.insertCell(1).textContent = conn.domain || "N/A";
                row.insertCell(2).textContent = conn.totalPackets;
                row.insertCell(3).textContent = conn.totalBytes;
                row.insertCell(4).textContent = conn.duration;
                row.insertCell(5).textContent = conn.flowRate.toFixed(2);
                row.insertCell(6).textContent = conn.applicationProtocol || "Unknown";
            });

            updateCharts(totalPackets, totalBytes);
            updatePieChart(tcpPackets, udpPackets);
        });
}

// Fetch metrics every 5 seconds
setInterval(updateMetrics, 5000);
updateMetrics(); // Initial load
