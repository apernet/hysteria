package webpanel

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hysteria Panel</title>
<style>
:root {
  color-scheme: light dark;
  --bg: #f5f7fb;
  --fg: #1f2937;
  --muted: #667085;
  --line: #d0d5dd;
  --panel: #ffffff;
  --accent: #1677ff;
  --danger: #c2410c;
  --ok: #047857;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #111827;
    --fg: #f3f4f6;
    --muted: #a4a7ae;
    --line: #374151;
    --panel: #1f2937;
    --accent: #60a5fa;
    --danger: #fb923c;
    --ok: #34d399;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  background: var(--bg);
  color: var(--fg);
  font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 18px clamp(16px, 4vw, 36px);
  border-bottom: 1px solid var(--line);
  background: var(--panel);
}
h1 { margin: 0; font-size: 20px; font-weight: 650; }
main { padding: 20px clamp(16px, 4vw, 36px) 32px; }
.toolbar, .tabs, .actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.path { color: var(--muted); font-family: ui-monospace, SFMono-Regular, Consolas, monospace; overflow-wrap: anywhere; }
button {
  border: 1px solid var(--line);
  border-radius: 6px;
  background: var(--panel);
  color: var(--fg);
  min-height: 36px;
  padding: 0 12px;
  cursor: pointer;
}
button.primary { background: var(--accent); border-color: var(--accent); color: white; }
button:disabled { opacity: .55; cursor: not-allowed; }
.tab { min-width: 96px; }
.tab.active { border-color: var(--accent); color: var(--accent); }
.notice {
  margin: 0 0 18px;
  padding: 10px 12px;
  border: 1px solid var(--line);
  border-left: 4px solid var(--accent);
  border-radius: 6px;
  background: var(--panel);
  color: var(--muted);
}
.status { min-height: 22px; margin: 12px 0; color: var(--muted); }
.status.ok { color: var(--ok); }
.status.err { color: var(--danger); }
.panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 16px;
}
.grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
}
fieldset {
  margin: 0;
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 12px;
}
legend { padding: 0 6px; color: var(--muted); font-weight: 650; }
label { display: block; margin: 8px 0 4px; color: var(--muted); }
input, select, textarea {
  width: 100%;
  min-height: 36px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: transparent;
  color: var(--fg);
  padding: 8px 10px;
  font: inherit;
}
textarea {
  min-height: 280px;
  resize: vertical;
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
}
.raw-editor { min-height: 58vh; }
.checkline {
  display: grid;
  grid-template-columns: 20px 1fr;
  align-items: center;
  gap: 8px;
  margin: 8px 0;
  color: var(--muted);
}
.checkline input { width: 18px; min-height: 18px; padding: 0; }
.hidden { display: none !important; }
#login {
  max-width: 380px;
  margin: 12vh auto 0;
}
@media (max-width: 980px) {
  .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 680px) {
  header { align-items: flex-start; flex-direction: column; }
  .grid { grid-template-columns: 1fr; }
  .tab { flex: 1; }
}
</style>
</head>
<body>
<header>
  <div>
    <h1>Hysteria Panel</h1>
    <div id="configPath" class="path"></div>
  </div>
  <div class="toolbar">
    <button id="reloadBtn" type="button">Reload</button>
    <button id="logoutBtn" type="button">Logout</button>
  </div>
</header>
<main>
  <section id="login" class="panel hidden">
    <h1>Login</h1>
    <label for="password">Password</label>
    <input id="password" type="password" autocomplete="current-password">
    <div class="actions" style="margin-top:12px">
      <button id="loginBtn" class="primary" type="button">Login</button>
    </div>
  </section>
  <section id="app" class="hidden">
    <p class="notice">Changes are written to the config file. Restart Hysteria for the running proxy to use the new values.</p>
    <div class="tabs" role="tablist">
      <button id="commonTab" class="tab active" type="button">Common</button>
      <button id="rawTab" class="tab" type="button">Raw config</button>
    </div>
    <div id="status" class="status"></div>
    <section id="commonView" class="panel">
      <div class="grid">
        <fieldset>
          <legend>Core</legend>
          <label for="listen">Listen</label>
          <input id="listen" placeholder=":443">
          <label class="checkline"><input id="disableUDP" type="checkbox"> Disable UDP</label>
          <label class="checkline"><input id="speedTest" type="checkbox"> Speed test</label>
          <label for="udpIdleTimeout">UDP idle timeout</label>
          <input id="udpIdleTimeout" placeholder="120s">
        </fieldset>
        <fieldset>
          <legend>Auth</legend>
          <label for="authType">Type</label>
          <select id="authType">
            <option value=""></option>
            <option value="password">password</option>
            <option value="userpass">userpass</option>
            <option value="http">http</option>
            <option value="command">command</option>
          </select>
          <label for="authPassword">Password</label>
          <input id="authPassword" type="password" autocomplete="new-password">
        </fieldset>
        <fieldset>
          <legend>TLS</legend>
          <label for="tlsCert">Cert</label>
          <input id="tlsCert">
          <label for="tlsKey">Key</label>
          <input id="tlsKey">
          <label for="sniGuard">SNI guard</label>
          <select id="sniGuard">
            <option value=""></option>
            <option value="dns-san">dns-san</option>
            <option value="strict">strict</option>
            <option value="disable">disable</option>
          </select>
          <label for="clientCA">Client CA</label>
          <input id="clientCA">
        </fieldset>
        <fieldset>
          <legend>Obfs</legend>
          <label for="obfsType">Type</label>
          <select id="obfsType">
            <option value=""></option>
            <option value="plain">plain</option>
            <option value="salamander">salamander</option>
            <option value="gecko">gecko</option>
          </select>
          <label for="obfsPassword">Password</label>
          <input id="obfsPassword" type="password" autocomplete="new-password">
        </fieldset>
        <fieldset>
          <legend>Bandwidth</legend>
          <label for="bandwidthUp">Up</label>
          <input id="bandwidthUp" placeholder="100 mbps">
          <label for="bandwidthDown">Down</label>
          <input id="bandwidthDown" placeholder="100 mbps">
        </fieldset>
        <fieldset>
          <legend>Congestion</legend>
          <label for="congestionType">Type</label>
          <select id="congestionType">
            <option value=""></option>
            <option value="bbr">bbr</option>
            <option value="brutal">brutal</option>
            <option value="reno">reno</option>
          </select>
          <label for="bbrProfile">BBR profile</label>
          <select id="bbrProfile">
            <option value=""></option>
            <option value="standard">standard</option>
            <option value="aggressive">aggressive</option>
          </select>
        </fieldset>
        <fieldset>
          <legend>Resolver</legend>
          <label for="resolverType">Type</label>
          <select id="resolverType">
            <option value=""></option>
            <option value="system">system</option>
            <option value="udp">udp</option>
            <option value="tcp">tcp</option>
            <option value="tls">tls</option>
            <option value="https">https</option>
          </select>
          <label for="resolverAddr">Address</label>
          <input id="resolverAddr">
          <label for="resolverTimeout">Timeout</label>
          <input id="resolverTimeout" placeholder="5s">
          <label for="resolverSNI">SNI</label>
          <input id="resolverSNI">
          <label class="checkline"><input id="resolverInsecure" type="checkbox"> Insecure</label>
        </fieldset>
        <fieldset>
          <legend>Sniff</legend>
          <label class="checkline"><input id="sniffEnable" type="checkbox"> Enable</label>
          <label for="sniffTimeout">Timeout</label>
          <input id="sniffTimeout" placeholder="1s">
          <label class="checkline"><input id="rewriteDomain" type="checkbox"> Rewrite domain</label>
          <label for="tcpPorts">TCP ports</label>
          <input id="tcpPorts">
          <label for="udpPorts">UDP ports</label>
          <input id="udpPorts">
        </fieldset>
        <fieldset>
          <legend>ACL</legend>
          <label for="aclFile">File</label>
          <input id="aclFile">
          <label for="aclInline">Inline rules</label>
          <textarea id="aclInline" style="min-height:120px"></textarea>
          <label for="geoip">GeoIP</label>
          <input id="geoip">
          <label for="geosite">GeoSite</label>
          <input id="geosite">
        </fieldset>
        <fieldset>
          <legend>Traffic stats</legend>
          <label for="statsListen">Listen</label>
          <input id="statsListen">
          <label for="statsSecret">Secret</label>
          <input id="statsSecret" type="password" autocomplete="new-password">
        </fieldset>
        <fieldset>
          <legend>Masquerade</legend>
          <label for="masqType">Type</label>
          <select id="masqType">
            <option value=""></option>
            <option value="404">404</option>
            <option value="file">file</option>
            <option value="proxy">proxy</option>
            <option value="string">string</option>
          </select>
          <label for="masqFileDir">File dir</label>
          <input id="masqFileDir">
          <label for="masqProxyURL">Proxy URL</label>
          <input id="masqProxyURL">
          <label class="checkline"><input id="masqProxyInsecure" type="checkbox"> Proxy insecure</label>
          <label for="masqString">String content</label>
          <textarea id="masqString" style="min-height:120px"></textarea>
        </fieldset>
      </div>
      <div class="actions" style="margin-top:16px">
        <button id="saveCommonBtn" class="primary" type="button">Save common settings</button>
      </div>
    </section>
    <section id="rawView" class="panel hidden">
      <textarea id="rawConfig" class="raw-editor" spellcheck="false"></textarea>
      <div class="actions" style="margin-top:16px">
        <button id="saveRawBtn" class="primary" type="button">Save raw config</button>
      </div>
    </section>
  </section>
</main>
<script>
(function () {
  var base = window.location.pathname.replace(/\/$/, "");
  var app = document.getElementById("app");
  var login = document.getElementById("login");
  var status = document.getElementById("status");
  var current = null;

  function api(path, options) {
    options = options || {};
    options.headers = options.headers || {};
    if (options.body && !options.headers["Content-Type"]) {
      options.headers["Content-Type"] = "application/json";
    }
    return fetch(base + path, options).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (body) {
        if (!res.ok) {
          throw new Error(body.error || res.statusText);
        }
        return body;
      });
    });
  }
  function setStatus(message, cls) {
    status.textContent = message || "";
    status.className = "status" + (cls ? " " + cls : "");
  }
  function showLogin() {
    app.classList.add("hidden");
    login.classList.remove("hidden");
  }
  function showApp() {
    login.classList.add("hidden");
    app.classList.remove("hidden");
  }
  function value(id, val) {
    var el = document.getElementById(id);
    if (val === undefined) {
      return el.type === "checkbox" ? el.checked : el.value;
    }
    if (el.type === "checkbox") {
      el.checked = !!val;
    } else {
      el.value = val || "";
    }
  }
  function populate(common) {
    value("listen", common.listen);
    value("disableUDP", common.disableUDP);
    value("speedTest", common.speedTest);
    value("udpIdleTimeout", common.udpIdleTimeout);
    value("authType", common.auth.type);
    value("authPassword", common.auth.password);
    value("tlsCert", common.tls.cert);
    value("tlsKey", common.tls.key);
    value("sniGuard", common.tls.sniGuard);
    value("clientCA", common.tls.clientCA);
    value("obfsType", common.obfs.type);
    value("obfsPassword", common.obfs.password);
    value("bandwidthUp", common.bandwidth.up);
    value("bandwidthDown", common.bandwidth.down);
    value("congestionType", common.congestion.type);
    value("bbrProfile", common.congestion.bbrProfile);
    value("resolverType", common.resolver.type);
    value("resolverAddr", common.resolver.addr);
    value("resolverTimeout", common.resolver.timeout);
    value("resolverSNI", common.resolver.sni);
    value("resolverInsecure", common.resolver.insecure);
    value("sniffEnable", common.sniff.enable);
    value("sniffTimeout", common.sniff.timeout);
    value("rewriteDomain", common.sniff.rewriteDomain);
    value("tcpPorts", common.sniff.tcpPorts);
    value("udpPorts", common.sniff.udpPorts);
    value("aclFile", common.acl.file);
    value("aclInline", common.acl.inline);
    value("geoip", common.acl.geoip);
    value("geosite", common.acl.geosite);
    value("statsListen", common.trafficStats.listen);
    value("statsSecret", common.trafficStats.secret);
    value("masqType", common.masquerade.type);
    value("masqFileDir", common.masquerade.fileDir);
    value("masqProxyURL", common.masquerade.proxyURL);
    value("masqProxyInsecure", common.masquerade.proxyInsecure);
    value("masqString", common.masquerade.stringContent);
  }
  function collect() {
    return {
      listen: value("listen"),
      disableUDP: value("disableUDP"),
      speedTest: value("speedTest"),
      udpIdleTimeout: value("udpIdleTimeout"),
      auth: { type: value("authType"), password: value("authPassword") },
      tls: { cert: value("tlsCert"), key: value("tlsKey"), sniGuard: value("sniGuard"), clientCA: value("clientCA") },
      obfs: { type: value("obfsType"), password: value("obfsPassword") },
      bandwidth: { up: value("bandwidthUp"), down: value("bandwidthDown") },
      congestion: { type: value("congestionType"), bbrProfile: value("bbrProfile") },
      resolver: { type: value("resolverType"), addr: value("resolverAddr"), timeout: value("resolverTimeout"), sni: value("resolverSNI"), insecure: value("resolverInsecure") },
      sniff: { enable: value("sniffEnable"), timeout: value("sniffTimeout"), rewriteDomain: value("rewriteDomain"), tcpPorts: value("tcpPorts"), udpPorts: value("udpPorts") },
      acl: { file: value("aclFile"), inline: value("aclInline"), geoip: value("geoip"), geosite: value("geosite") },
      trafficStats: { listen: value("statsListen"), secret: value("statsSecret") },
      masquerade: { type: value("masqType"), fileDir: value("masqFileDir"), proxyURL: value("masqProxyURL"), proxyInsecure: value("masqProxyInsecure"), stringContent: value("masqString") }
    };
  }
  function load() {
    setStatus("Loading...");
    api("/api/state").then(function (state) {
      current = state;
      document.getElementById("configPath").textContent = state.configPath;
      document.getElementById("rawConfig").value = state.config || "";
      populate(state.common);
      showApp();
      setStatus("");
    }).catch(function (err) {
      setStatus(err.message, "err");
      showLogin();
    });
  }
  function saveCommon() {
    setStatus("Saving...");
    api("/api/settings", {
      method: "PUT",
      headers: { "X-Hysteria-Panel": "1" },
      body: JSON.stringify(collect())
    }).then(function () {
      setStatus("Saved. Restart Hysteria to apply the new config.", "ok");
      load();
    }).catch(function (err) {
      setStatus(err.message, "err");
    });
  }
  function saveRaw() {
    setStatus("Saving...");
    api("/api/config", {
      method: "PUT",
      headers: { "X-Hysteria-Panel": "1" },
      body: JSON.stringify({ config: document.getElementById("rawConfig").value })
    }).then(function () {
      setStatus("Saved. Restart Hysteria to apply the new config.", "ok");
      load();
    }).catch(function (err) {
      setStatus(err.message, "err");
    });
  }
  function switchTab(raw) {
    document.getElementById("commonTab").classList.toggle("active", !raw);
    document.getElementById("rawTab").classList.toggle("active", raw);
    document.getElementById("commonView").classList.toggle("hidden", raw);
    document.getElementById("rawView").classList.toggle("hidden", !raw);
    setStatus("");
  }
  document.getElementById("loginBtn").addEventListener("click", function () {
    api("/api/login", {
      method: "POST",
      body: JSON.stringify({ password: document.getElementById("password").value })
    }).then(load).catch(function (err) { setStatus(err.message, "err"); });
  });
  document.getElementById("password").addEventListener("keydown", function (ev) {
    if (ev.key === "Enter") {
      document.getElementById("loginBtn").click();
    }
  });
  document.getElementById("logoutBtn").addEventListener("click", function () {
    api("/api/logout", { method: "POST" }).finally(function () {
      showLogin();
      setStatus("");
    });
  });
  document.getElementById("reloadBtn").addEventListener("click", load);
  document.getElementById("saveCommonBtn").addEventListener("click", saveCommon);
  document.getElementById("saveRawBtn").addEventListener("click", saveRaw);
  document.getElementById("commonTab").addEventListener("click", function () { switchTab(false); });
  document.getElementById("rawTab").addEventListener("click", function () { switchTab(true); });
  load();
})();
</script>
</body>
</html>`
