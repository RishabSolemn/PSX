function isBlockedHost(host) {
  const blocked = ["0.0.0.0", "127.0.0.1", "localhost"];
  return blocked.includes(host.trim());
}

let pendingScan = null;

document.getElementById("scanForm").addEventListener("submit", function(e) {
  e.preventDefault();
  const host = document.getElementById("host").value.trim();
  const portRange = document.getElementById("portRange").value.trim() || "1-1024";
  const user = document.getElementById("username").value.trim() || "Anonymous";

  if (isBlockedHost(host)) {
    alert("❌ Scanning this host is not allowed: " + host);
    return;
  }

  pendingScan = { host, portRange, user };
  document.getElementById("permissionPopup").style.display = "flex";
});

document.getElementById("allowScan").onclick = () => {
  if (!pendingScan) return;
  document.getElementById("permissionPopup").style.display = "none";
  document.getElementById("loadingScreen").style.display = "flex";

  fetch("/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      host: pendingScan.host,
      range: pendingScan.portRange,
      name: pendingScan.user
    })
  })
  .then(res => res.json())
  .then(data => {
    document.getElementById("loadingScreen").style.display = "none";
    if (data.error) {
      alert(data.error);
      return;
    }
    document.getElementById("scanResult").style.display = "block";
    document.getElementById("targetIP").innerText = data.ip;
    document.getElementById("geoInfo").innerText = `${data.geo.city}, ${data.geo.country}`;
    document.getElementById("threatLevel").innerText = data.threat_level;
    document.getElementById("openPorts").innerText = data.open_ports.join(", ") || "None";

    const bar = document.getElementById("threatBar");
    if (data.threat_level === "Low") {
      bar.style.backgroundColor = "green";
      bar.style.width = "20%";
    } else if (data.threat_level === "Medium") {
      bar.style.backgroundColor = "orange";
      bar.style.width = "60%";
    } else {
      bar.style.backgroundColor = "red";
      bar.style.width = "100%";
    }
  })
  .catch(err => {
    document.getElementById("loadingScreen").style.display = "none";
    alert("An error occurred.");
    console.error(err);
  });
};

document.getElementById("denyScan").onclick = () => {
  window.close(); // closes tab if possible
};
