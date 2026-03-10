document.addEventListener("DOMContentLoaded", () => {
  const globalDomain = document.getElementById("global-domain");
  const globalDns = document.getElementById("global-dns");
  const pingHttpHost = document.getElementById("ping-http-host");

  // Fetch network info
  fetch("/api/netinfo")
    .then(r => r.json())
    .then(info => {
      const el = document.getElementById("net-info");
      let html = "";
      if (info.hostname) {
        html += '<span class="net-info-item"><span class="net-info-label">Host:</span> ' + escapeHtml(info.hostname) + '</span>';
      }
      if (info.ips && info.ips.length) {
        html += '<span class="net-info-item"><span class="net-info-label">IP:</span> ' + info.ips.map(ip => escapeHtml(ip)).join(", ") + '</span>';
      }
      if (info.dns_server) {
        html += '<span class="net-info-item"><span class="net-info-label">DNS:</span> ' + escapeHtml(info.dns_server) + '</span>';
      }
      el.innerHTML = html || "No network info available";
    })
    .catch(() => {
      document.getElementById("net-info").textContent = "Failed to load network info";
    });

  // Sync global domain to HTTP URL field
  globalDomain.addEventListener("input", () => {
    pingHttpHost.value = globalDomain.value;
  });

  // Tab switching
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
    });
  });

  // Ping - HTTP checkbox toggles URL field visibility
  const pingHttpCheck = document.getElementById("ping-http");
  const pingHttpGroup = document.getElementById("ping-http-group");

  pingHttpCheck.addEventListener("change", () => {
    pingHttpGroup.style.display = pingHttpCheck.checked ? "flex" : "none";
  });

  // Ping
  let pingES = null;
  const pingStart = document.getElementById("ping-start");
  const pingStop = document.getElementById("ping-stop");
  const pingOutput = document.getElementById("ping-output");

  pingStart.addEventListener("click", () => {
    const domain = globalDomain.value.trim();
    if (!domain) return;

    const isHttp = pingHttpCheck.checked;
    let host;
    if (isHttp) {
      host = "https://" + pingHttpHost.value.trim();
    } else {
      host = domain;
    }

    const icmp = !isHttp;

    pingOutput.textContent = "";
    pingStart.disabled = true;
    pingStop.disabled = false;

    const timeoutVal = document.getElementById("ping-timeout").value.trim();
    let url = "/api/ping/stream?host=" + encodeURIComponent(host) + "&icmp=" + icmp;
    if (timeoutVal) url += "&timeout=" + encodeURIComponent(timeoutVal);
    pingES = new EventSource(url);
    pingES.onmessage = (e) => {
      const r = JSON.parse(e.data);
      if (r.success) {
        if (icmp) {
          pingOutput.textContent += "seq=" + r.seq + ": bytes=" + r.bytes + " addr=" + r.addr + " time=" + formatDuration(r.rtt) + "\n";
        } else {
          pingOutput.textContent += "seq=" + r.seq + ": status=" + r.status_code + " time=" + formatDuration(r.rtt) + "\n";
        }
      } else {
        pingOutput.textContent += "seq=" + r.seq + ": error - " + r.error + "\n";
      }
      pingOutput.scrollTop = pingOutput.scrollHeight;
    };
    pingES.addEventListener("done", () => {
      stopPing();
    });
    pingES.onerror = () => {
      stopPing();
    };
  });

  pingStop.addEventListener("click", stopPing);

  function stopPing() {
    if (pingES) { pingES.close(); pingES = null; }
    pingStart.disabled = false;
    pingStop.disabled = true;
  }

  // Traceroute
  let trES = null;
  const trStart = document.getElementById("tr-start");
  const trStop = document.getElementById("tr-stop");
  const trOutput = document.getElementById("tr-output");

  trStart.addEventListener("click", () => {
    const host = globalDomain.value.trim();
    if (!host) return;

    trOutput.textContent = "";
    trStart.disabled = true;
    trStop.disabled = false;

    trES = new EventSource("/api/traceroute/stream?host=" + encodeURIComponent(host));
    trES.addEventListener("info", (e) => {
      const info = JSON.parse(e.data);
      trOutput.textContent += "traceroute to " + host + " (" + info.dst_ip + ")\n\n";
    });
    trES.onmessage = (e) => {
      const h = JSON.parse(e.data);
      if (h.timeout) {
        trOutput.textContent += pad(h.ttl) + "  *\n";
      } else if (h.error) {
        trOutput.textContent += pad(h.ttl) + "  error: " + h.error + "\n";
      } else {
        let line = pad(h.ttl) + "  " + (h.host !== h.addr ? h.host + " (" + h.addr + ")" : h.addr) + "  " + formatDuration(h.rtt);
        trOutput.textContent += line + "\n";
      }
      trOutput.scrollTop = trOutput.scrollHeight;
    };
    trES.addEventListener("done", () => { stopTr(); });
    trES.addEventListener("error", (e) => {
      if (e.data) {
        const err = JSON.parse(e.data);
        trOutput.textContent += "Error: " + err.error + "\n";
      }
      stopTr();
    });
  });

  trStop.addEventListener("click", stopTr);

  function stopTr() {
    if (trES) { trES.close(); trES = null; }
    trStart.disabled = false;
    trStop.disabled = true;
  }

  // NSLookup
  document.getElementById("ns-lookup").addEventListener("click", async () => {
    const domain = globalDomain.value.trim();
    if (!domain) return;
    const server = globalDns.value.trim();
    const output = document.getElementById("ns-output");
    output.textContent = "Looking up...\n";

    try {
      const resp = await fetch("/api/nslookup", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({domain, server})
      });
      const r = await resp.json();

      let text = "Domain: " + r.domain + "\n\n";
      if (r.addrs && r.addrs.length) {
        text += "Addresses:\n";
        r.addrs.forEach(a => text += "  " + a + "\n");
      }
      if (r.cname) text += "\nCNAME: " + r.cname + "\n";
      if (r.mx && r.mx.length) {
        text += "\nMX Records:\n";
        r.mx.forEach(m => text += "  " + m.host + " (priority " + m.pref + ")\n");
      }
      if (r.ns && r.ns.length) {
        text += "\nName Servers:\n";
        r.ns.forEach(n => text += "  " + n + "\n");
      }
      if (r.txt && r.txt.length) {
        text += "\nTXT Records:\n";
        r.txt.forEach(t => text += "  " + t + "\n");
      }
      text += "\nQuery time: " + r.time;
      output.textContent = text;
    } catch (e) {
      output.textContent = "Error: " + e.message;
    }
  });

  // Dig
  document.getElementById("dig-query").addEventListener("click", async () => {
    const domain = globalDomain.value.trim();
    if (!domain) return;
    const qtype = document.getElementById("dig-type").value;
    const server = globalDns.value.trim();
    const output = document.getElementById("dig-output");
    output.textContent = "Querying...\n";

    try {
      const resp = await fetch("/api/dig", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({domain, type: qtype, server})
      });
      const r = await resp.json();

      if (r.error) {
        output.textContent = "Error: " + r.error;
        return;
      }

      let text = ";; ->>HEADER<<- rcode: " + r.rcode + ", authoritative: " + r.authoritative + "\n";
      text += ";; SERVER: " + r.server + "\n";
      text += ";; QUERY: " + r.domain + " " + r.query_type + "\n\n";

      if (r.answer && r.answer.length) {
        text += ";; ANSWER SECTION:\n";
        r.answer.forEach(rec => {
          text += rec.name.padEnd(30) + " " + rec.ttl + "\tIN\t" + rec.type + "\t" + rec.value + "\n";
        });
      }
      if (r.authority && r.authority.length) {
        text += "\n;; AUTHORITY SECTION:\n";
        r.authority.forEach(rec => {
          text += rec.name.padEnd(30) + " " + rec.ttl + "\tIN\t" + rec.type + "\t" + rec.value + "\n";
        });
      }
      if (r.additional && r.additional.length) {
        text += "\n;; ADDITIONAL SECTION:\n";
        r.additional.forEach(rec => {
          text += rec.name.padEnd(30) + " " + rec.ttl + "\tIN\t" + rec.type + "\t" + rec.value + "\n";
        });
      }
      text += "\n;; Query time: " + r.query_time;
      output.textContent = text;
    } catch (e) {
      output.textContent = "Error: " + e.message;
    }
  });

  // Dig All
  document.getElementById("digall-query").addEventListener("click", async () => {
    const domain = globalDomain.value.trim();
    if (!domain) return;
    const server = globalDns.value.trim();
    const output = document.getElementById("digall-output");
    output.innerHTML = '<div class="digall-loading">Querying all record types...</div>';

    try {
      const resp = await fetch("/api/dig/all", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({domain, server})
      });
      const results = await resp.json();

      const typeOrder = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "PTR"];
      let html = "";

      for (const t of typeOrder) {
        const r = results[t];
        if (!r) continue;

        const records = r.answer || [];
        const count = records.length;
        const badgeClass = count > 0 ? "has-records" : "no-records";
        const badgeText = count > 0 ? count + " record" + (count > 1 ? "s" : "") : "none";

        html += '<div class="digall-card">';
        html += '<div class="digall-card-header">';
        html += '<span class="digall-card-type">' + t + '</span>';
        html += '<span class="digall-card-badge ' + badgeClass + '">' + badgeText + '</span>';
        html += '</div>';
        html += '<div class="digall-card-body">';

        if (count === 0) {
          html += '<div class="digall-empty">No records</div>';
        } else {
          for (const rec of records) {
            html += '<div class="digall-card-row">';
            html += '<span class="digall-ttl">TTL ' + rec.ttl + '</span>';
            html += '<span class="digall-value">' + escapeHtml(rec.value) + '</span>';
            html += '</div>';
          }
        }

        html += '</div></div>';
      }

      output.innerHTML = html;
    } catch (e) {
      output.innerHTML = '<div class="digall-loading">Error: ' + escapeHtml(e.message) + '</div>';
    }
  });

  // Mail Auth
  document.getElementById("mailauth-check").addEventListener("click", async () => {
    const domain = globalDomain.value.trim();
    if (!domain) return;
    const server = globalDns.value.trim();
    const output = document.getElementById("mailauth-output");
    output.innerHTML = '<div class="mailauth-loading">Checking mail authentication records...</div>';

    try {
      const resp = await fetch("/api/mailauth", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({domain, server})
      });
      const r = await resp.json();
      let html = "";

      // SPF
      html += renderMailAuthSection("SPF", r.spf.found, r.spf.raw, r.spf.parsed,
        r.spf.found ? "Configured" : "Not found",
        r.spf.found ? "pass" : "fail");

      // DKIM
      html += '<div class="mailauth-section">';
      html += '<div class="mailauth-header">';
      html += '<span class="mailauth-title">DKIM</span>';
      const dkimFound = r.dkim.selectors && r.dkim.selectors.length > 0;
      const dkimStatus = dkimFound ? "pass" : "warn";
      const dkimLabel = dkimFound ? r.dkim.selectors.length + " selector(s) found" : "No common selectors found";
      html += '<span class="mailauth-status ' + dkimStatus + '">' + dkimLabel + '</span>';
      html += '</div>';
      html += '<div class="mailauth-body">';
      if (dkimFound) {
        html += '<div class="mailauth-dkim-list">';
        for (const sel of r.dkim.selectors) {
          html += '<div class="mailauth-dkim-item">';
          html += '<div class="mailauth-dkim-selector">' + escapeHtml(sel.selector) + '._domainkey.' + escapeHtml(domain) + '</div>';
          if (sel.raw) {
            html += '<div class="mailauth-dkim-raw">' + escapeHtml(sel.raw) + '</div>';
          }
          html += '</div>';
        }
        html += '</div>';
      } else {
        html += '<div class="mailauth-none">No DKIM records found for common selectors (default, google, selector1, selector2, k1, ...)</div>';
      }
      html += '</div></div>';

      // DMARC
      html += renderMailAuthSection("DMARC", r.dmarc.found, r.dmarc.raw, r.dmarc.parsed,
        r.dmarc.found ? "Configured" : "Not found",
        r.dmarc.found ? "pass" : "fail");

      // BIMI
      html += renderMailAuthSection("BIMI", r.bimi.found, r.bimi.raw, r.bimi.parsed,
        r.bimi.found ? "Configured" : "Not found",
        r.bimi.found ? "pass" : "warn");

      output.innerHTML = html;
    } catch (e) {
      output.innerHTML = '<div class="mailauth-loading">Error: ' + escapeHtml(e.message) + '</div>';
    }
  });

  // TLS Cert
  document.getElementById("tlscert-check").addEventListener("click", async () => {
    const host = globalDomain.value.trim();
    if (!host) return;
    const port = document.getElementById("tlscert-port").value.trim() || "443";
    const output = document.getElementById("tlscert-output");
    output.innerHTML = '<div class="tlscert-loading">Checking TLS certificate...</div>';

    try {
      const resp = await fetch("/api/tlscert", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({host, port})
      });
      const r = await resp.json();

      if (r.error) {
        output.innerHTML = '<div class="tlscert-loading">Error: ' + escapeHtml(r.error) + '</div>';
        return;
      }

      let html = "";

      // Connection info
      html += '<div class="tlscert-section">';
      html += '<div class="tlscert-header">';
      html += '<span class="tlscert-title">Connection Info</span>';
      const validClass = r.valid ? "pass" : "fail";
      const validLabel = r.valid ? "Valid" : "Invalid";
      html += '<span class="mailauth-status ' + validClass + '">' + validLabel + '</span>';
      html += '</div>';
      html += '<div class="tlscert-body">';
      html += tlscertRow("Host", r.host + ":" + r.port);
      html += tlscertRow("TLS Version", r.tls_version);
      html += tlscertRow("Cipher Suite", r.cipher_suite);
      if (r.validation_error) {
        html += tlscertRow("Validation Error", r.validation_error);
      }
      html += tlscertRow("Check Time", r.check_time);
      html += '</div></div>';

      // Certificates
      if (r.certificates) {
        for (let i = 0; i < r.certificates.length; i++) {
          const cert = r.certificates[i];
          const title = i === 0 ? "Server Certificate" : "Chain Certificate #" + i;
          html += renderCertSection(title, cert);
        }
      }

      output.innerHTML = html;
    } catch (e) {
      output.innerHTML = '<div class="tlscert-loading">Error: ' + escapeHtml(e.message) + '</div>';
    }
  });

  function renderCertSection(title, cert) {
    let html = '<div class="tlscert-section">';
    html += '<div class="tlscert-header">';
    html += '<span class="tlscert-title">' + escapeHtml(title) + '</span>';

    // Expiry badge
    if (cert.expiry_warning === "EXPIRED") {
      html += '<span class="mailauth-status fail">EXPIRED</span>';
    } else if (cert.expiry_warning === "Expiring soon") {
      html += '<span class="mailauth-status warn">Expiring soon (' + cert.days_until_expiry + 'd)</span>';
    } else {
      html += '<span class="mailauth-status pass">' + cert.days_until_expiry + ' days left</span>';
    }

    html += '</div>';
    html += '<div class="tlscert-body">';

    html += tlscertRow("Subject", formatSubject(cert.subject));
    html += tlscertRow("Issuer", formatSubject(cert.issuer));
    html += tlscertRow("Serial", cert.serial_number);
    html += tlscertRow("Not Before", cert.not_before);
    html += tlscertRow("Not After", cert.not_after);
    html += tlscertRow("Signature", cert.signature_algorithm);
    html += tlscertRow("Public Key", cert.public_key_algorithm + " " + cert.public_key_size + " bits");
    html += tlscertRow("Is CA", String(cert.is_ca));
    html += tlscertRow("Version", String(cert.version));

    // SANs
    const allSans = [].concat(
      (cert.sans.dns || []).map(s => "DNS:" + s),
      (cert.sans.ips || []).map(s => "IP:" + s),
      (cert.sans.email || []).map(s => "Email:" + s),
      (cert.sans.uris || []).map(s => "URI:" + s)
    );
    if (allSans.length > 0) {
      html += '<div class="tlscert-row">';
      html += '<span class="tlscert-label">SANs</span>';
      html += '<span class="tlscert-value"><div class="tlscert-san-tags">';
      for (const san of allSans) {
        html += '<span class="tlscert-san-tag">' + escapeHtml(san) + '</span>';
      }
      html += '</div></span>';
      html += '</div>';
    }

    html += '</div></div>';
    return html;
  }

  function tlscertRow(label, value) {
    return '<div class="tlscert-row"><span class="tlscert-label">' + escapeHtml(label) + '</span><span class="tlscert-value">' + escapeHtml(value) + '</span></div>';
  }

  function formatSubject(s) {
    const parts = [];
    if (s.cn) parts.push("CN=" + s.cn);
    if (s.org) parts.push("O=" + s.org);
    if (s.ou) parts.push("OU=" + s.ou);
    if (s.country) parts.push("C=" + s.country);
    if (s.province) parts.push("ST=" + s.province);
    if (s.locality) parts.push("L=" + s.locality);
    return parts.join(", ") || "(empty)";
  }

  function renderMailAuthSection(title, found, raw, parsed, label, statusClass) {
    let html = '<div class="mailauth-section">';
    html += '<div class="mailauth-header">';
    html += '<span class="mailauth-title">' + title + '</span>';
    html += '<span class="mailauth-status ' + statusClass + '">' + label + '</span>';
    html += '</div>';
    html += '<div class="mailauth-body">';
    if (!found) {
      html += '<div class="mailauth-none">No ' + title + ' record found</div>';
    } else {
      if (raw) {
        html += '<div class="mailauth-raw">' + escapeHtml(raw) + '</div>';
      }
      if (parsed && Object.keys(parsed).length > 0) {
        html += '<div class="mailauth-tags">';
        for (const [k, v] of Object.entries(parsed)) {
          html += '<span class="mailauth-tag">';
          html += '<span class="mailauth-tag-key">' + escapeHtml(k) + '</span>';
          if (v) {
            html += '<span class="mailauth-tag-value">' + escapeHtml(v) + '</span>';
          }
          html += '</span>';
        }
        html += '</div>';
      }
    }
    html += '</div></div>';
    return html;
  }

  function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  // Helpers
  function formatDuration(ns) {
    if (ns < 1000) return ns + "ns";
    if (ns < 1000000) return (ns / 1000).toFixed(1) + "µs";
    if (ns < 1000000000) return (ns / 1000000).toFixed(1) + "ms";
    return (ns / 1000000000).toFixed(2) + "s";
  }

  function pad(n) {
    return String(n).padStart(2, " ");
  }
});
