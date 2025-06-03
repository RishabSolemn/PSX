window.onload = () => {
  const questionnaireModal = new bootstrap.Modal(document.getElementById('questionnaireModal'));
  questionnaireModal.show();
};

function showPermissionModal() {
  const name = document.getElementById('userName').value.trim();
  const host = document.getElementById('targetHost').value.trim();

  if (!name || !host || host === "0.0.0.0") {
    alert("Please fill out your name and a valid target.");
    return;
  }

  const permissionModal = new bootstrap.Modal(document.getElementById('permissionModal'));
  permissionModal.show();
}

function closePage() {
  window.close();
}

function startScan() {
  const permissionModalEl = document.getElementById('permissionModal');
  const permissionModal = bootstrap.Modal.getInstance(permissionModalEl);
  permissionModal.hide();

  // Hide backdrop manually if needed
  document.querySelectorAll('.modal-backdrop').forEach(el => el.remove());

  const overlay = document.getElementById('loadingOverlay');
  overlay.classList.remove('d-none');

  const name = document.getElementById('userName').value.trim();
  const host = document.getElementById('targetHost').value.trim();
  const range = document.getElementById('portRange').value.trim();

  fetch('/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, host, range })
  })
    .then(res => res.json())
    .then(data => {
      overlay.classList.add('d-none');
      if (data.error) {
        alert("Scan failed: " + data.error);
        return;
      }
      displayResults(data);
    })
    .catch(err => {
      overlay.classList.add('d-none');
      alert("Scan error: " + err.message);
    });
}

function displayResults(data) {
  const section = document.getElementById('resultsSection');
  const portContainer = document.getElementById('portResults');
  const geoInfo = document.getElementById('geoInfo');
  const deceptionAlert = document.getElementById('deceptionAlert');
  const threatBar = document.getElementById('threatBar');

  section.classList.remove('d-none');
  portContainer.innerHTML = '';

  if (Array.isArray(data.open_ports)) {
    data.open_ports.forEach(p => {
      const div = document.createElement('div');
      div.classList.add('open-port');
      div.innerText = `Port ${p.port} – ${p.description || 'Unknown'}`;
      portContainer.appendChild(div);
    });
  } else {
    portContainer.innerText = 'No open ports detected.';
  }

  // Geo Info
  if (data.geo) {
    geoInfo.innerText = `Location: ${data.geo.city}, ${data.geo.country} [${data.geo.lat}, ${data.geo.lon}]`;
  } else {
    geoInfo.innerText = 'Location data unavailable.';
  }

  // Deception Alert
  if (data.deception) {
    deceptionAlert.innerText = '⚠️ DNS/CDN Deception Detected';
  } else {
    deceptionAlert.innerText = '';
  }

  // Threat Level Calculation
  const count = data.open_ports?.length || 0;
  let level = 'Low';
  let percent = 25;
  let bg = 'bg-success';

  if (count >= 50) {
    level = 'High';
    percent = 100;
    bg = 'bg-danger';
  } else if (count >= 10) {
    level = 'Medium';
    percent = 60;
    bg = 'bg-warning';
  }

  threatBar.className = `progress-bar ${bg}`;
  threatBar.style.width = `${percent}%`;
  threatBar.innerText = level;
}
function isBlockedHost(host) {
    const blocked = ["0.0.0.0", "127.0.0.1", "localhost"];
    return blocked.includes(host.trim());
}

document.getElementById("scanForm").addEventListener("submit", function (e) {
    e.preventDefault();
    const host = document.getElementById("host").value.trim();
    const portRange = document.getElementById("portRange").value.trim() || "1-1024";
    const user = document.getElementById("username").value.trim() || "Anonymous";

    if (isBlockedHost(host)) {
        alert("❌ Scanning this host is not allowed: " + host);
        return;
    }

    fetch("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ host, range: portRange, name: user })
    })
    .then(res => res.json())
    .then(data => {
        if (data.error) {
            alert(data.error);
        } else {
            // Update UI with scan result
            console.log("Scan successful:", data);
        }
    })
    .catch(err => console.error("Scan error:", err));
});

function downloadLog() {
  window.location.href = '/download-log';
}
