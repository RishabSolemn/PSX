function showPermissionModal() {
  const name = document.getElementById('userName').value;
  const host = document.getElementById('targetHost').value;
  if (!name || !host) {
    alert("Please fill out your name and target.");
    return;
  }
  new bootstrap.Modal(document.getElementById('permissionModal')).show();
}

function closePage() {
  window.close();
}

function startScan() {
  document.getElementById('permissionModal').classList.remove('show');
  document.querySelector('.modal-backdrop').remove();

  const overlay = document.getElementById('loadingOverlay');
  overlay.classList.remove('d-none');

  const name = document.getElementById('userName').value;
  const host = document.getElementById('targetHost').value;
  const range = document.getElementById('portRange').value;

  fetch('/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, host, range })
  })
    .then(res => res.json())
    .then(data => {
      overlay.classList.add('d-none');
      displayResults(data);
    });
}

function displayResults(data) {
  const section = document.getElementById('resultsSection');
  const portContainer = document.getElementById('portResults');
  const geoInfo = document.getElementById('geoInfo');
  const threatBar = document.getElementById('threatBar');

  section.classList.remove('d-none');
  portContainer.innerHTML = '';
  data.open_ports.forEach(p => {
    const div = document.createElement('div');
    div.classList.add('open-port');
    div.innerText = `Port ${p.port} – ${p.description}`;
    portContainer.appendChild(div);
  });

  geoInfo.innerText = `Location: ${data.geo.city}, ${data.geo.country} [${data.geo.lat}, ${data.geo.lon}]`;

  if (data.deception) {
    document.getElementById('deceptionAlert').innerText = '⚠️ DNS/CDN Deception Detected';
  }

  // Threat level bar
  let level = 'Low';
  let percent = 25;
  let bg = 'bg-success';

  if (data.open_ports.length >= 50) {
    level = 'High';
    percent = 100;
    bg = 'bg-danger';
  } else if (data.open_ports.length >= 10) {
    level = 'Medium';
    percent = 60;
    bg = 'bg-warning';
  }

  threatBar.className = `progress-bar ${bg}`;
  threatBar.style.width = `${percent}%`;
  threatBar.innerText = level;
}

function downloadLog() {
  window.location.href = '/download-log';
}

window.onload = () => {
  new bootstrap.Modal(document.getElementById('questionnaireModal')).show();
};

