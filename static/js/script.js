
document.addEventListener('DOMContentLoaded', function () {
    const modal = document.getElementById('agePermissionModal');
    const yesBtn = document.getElementById('yesPermission');
    const noBtn = document.getElementById('noPermission');

    yesBtn.onclick = () => modal.remove();
    noBtn.onclick = () => window.close();

    const form = document.getElementById('scanForm');
    const loadingScreen = document.getElementById('loadingScreen');
    const results = document.getElementById('results');
    const scanTimeline = document.getElementById('scanTimeline');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        loadingScreen.classList.remove('d-none');
        results.style.display = 'none';

        const formData = new FormData(form);
        const response = await fetch('/scan', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        loadingScreen.classList.add('d-none');
        results.style.display = 'block';
        scanTimeline.innerHTML = '';

        data.results.forEach((port, i) => {
            let threat = 'Low';
            if (data.results.length >= 50) threat = 'High';
            else if (data.results.length >= 10) threat = 'Medium';

            scanTimeline.innerHTML += `
                <div class="alert alert-dark mt-2">
                    <strong>Port ${port.port}</strong> (${port.service || 'Unknown'}) – Status: ${port.status}
                    <span class="badge bg-${threat === 'High' ? 'danger' : threat === 'Medium' ? 'warning' : 'success'}">${threat} Threat</span>
                </div>
            `;
        });
    });
});
