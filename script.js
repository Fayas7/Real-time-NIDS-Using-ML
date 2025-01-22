// Dashboard state
let stats = {
    totalPackets: 0,
    totalAnomalies: 0,
    startTime: new Date(),
    trafficData: {
        normal: [],
        anomaly: []
    }
};

// Initialize Chart.js
const ctx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [
            {
                label: 'Normal Traffic',
                data: [],
                borderColor: '#2ecc71',
                tension: 0.4,
                fill: false
            },
            {
                label: 'Anomalies',
                data: [],
                borderColor: '#e74c3c',
                tension: 0.4,
                fill: false
            }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: {
                beginAtZero: true
            }
        },
        animation: {
            duration: 0
        }
    }
});

// WebSocket connection
const ws = new WebSocket(`ws://${window.location.host}/ws`);

ws.onopen = function() {
    console.log('WebSocket connection established');
    document.getElementById('systemStatus').textContent = 'Active';
    document.getElementById('systemStatus').style.backgroundColor = '#2ecc71';
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    updateDashboard(data);
};

ws.onclose = function() {
    console.log('WebSocket connection closed');
    document.getElementById('systemStatus').textContent = 'Disconnected';
    document.getElementById('systemStatus').style.backgroundColor = '#e74c3c';
};

ws.onerror = function(error) {
    console.error('WebSocket error:', error);
    document.getElementById('systemStatus').textContent = 'Error';
    document.getElementById('systemStatus').style.backgroundColor = '#e74c3c';
};

function updateDashboard(data) {
    // Update statistics
    stats.totalPackets++;
    if (data.prediction_label === 'anomaly') {
        stats.totalAnomalies++;
    }

    // Update counters
    document.getElementById('totalPackets').textContent = stats.totalPackets;
    document.getElementById('totalAnomalies').textContent = stats.totalAnomalies;
    document.getElementById('detectionRate').textContent = 
        `${((stats.totalAnomalies / stats.totalPackets) * 100).toFixed(2)}%`;
    document.getElementById('activeSince').textContent = 
        stats.startTime.toLocaleTimeString();

    // Update traffic chart
    const timestamp = new Date().toLocaleTimeString();
    trafficChart.data.labels.push(timestamp);
    trafficChart.data.datasets[0].data.push(
        data.prediction_label === 'normal' ? 1 : 0
    );
    trafficChart.data.datasets[1].data.push(
        data.prediction_label === 'anomaly' ? 1 : 0
    );

    // Keep only last 50 data points
    if (trafficChart.data.labels.length > 50) {
        trafficChart.data.labels.shift();
        trafficChart.data.datasets.forEach(dataset => dataset.data.shift());
    }
    trafficChart.update();

    // Add to activity table
    const table = document.getElementById('activityTable');
    const row = table.insertRow(0);
    row.innerHTML = `
        <td>${new Date().toLocaleTimeString()}</td>
        <td>${data.features['ip.src']}</td>
        <td>${data.features['ip.dst']}</td>
        <td class="status-${data.prediction_label}">
            ${data.prediction_label.toUpperCase()}
        </td>
    `;

    // Keep only last 10 rows
    if (table.rows.length > 10) {
        table.deleteRow(table.rows.length - 1);
    }

    // Add alert if anomaly detected
    if (data.prediction_label === 'anomaly') {
        const alertsContainer = document.getElementById('alertsContainer');
        const alert = document.createElement('div');
        alert.className = 'alert';
        alert.innerHTML = `
            <strong>Intrusion Detected!</strong><br>
            Time: ${new Date().toLocaleTimeString()}<br>
            Source IP: ${data.features['ip.src']}<br>
            Destination IP: ${data.features['ip.dst']}<br>
            Ports: ${data.features['tcp.srcport']} → ${data.features['tcp.dstport']}
        `;
        alertsContainer.insertBefore(alert, alertsContainer.firstChild);

        // Keep only last 50 alerts
        if (alertsContainer.children.length > 50) {
            alertsContainer.removeChild(alertsContainer.lastChild);
        }
    }
}

// Automatically reconnect WebSocket if connection is lost
setInterval(() => {
    if (ws.readyState === WebSocket.CLOSED) {
        console.log('Attempting to reconnect WebSocket...');
        location.reload();
    }
}, 5000);