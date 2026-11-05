// The admin app. Built in step 09 (see docs/steps/09-admin-ui.md).
// Rules: token in a JS variable only, never in storage; every server string
// rendered with textContent. No framework, no build step, no third-party JS,
// no external URL: every request is a relative path under /api/v1.

const app = document.getElementById("app");

// Token lives in a closure only. A page reload loses it on purpose: the admin
// token is not a thing that survives a browser session.
let accessToken = "";
let refreshToken = "";
const TIMEOUT_MS = 20000;
let pollTimer = null;

async function api(path, opts = {}, allowRetry = true) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  const init = {
    method: opts.method || "GET",
    credentials: "same-origin",
    signal: controller.signal,
    headers: {},
  };
  if (accessToken) init.headers["Authorization"] = "Bearer " + accessToken;
  if (opts.body) init.headers["Content-Type"] = "application/json";
  if (opts.body) init.body = opts.body;
  let res;
  try {
    res = await fetch("/api/v1" + path, init);
  } catch (networkErr) {
    clearTimeout(timer);
    if (allowRetry) return api(path, opts, false);
    throw networkErr;
  }
  clearTimeout(timer);
  if (res.status === 401 && allowRetry && refreshToken) {
    // Refresh once; do not retry on 401 after a failed refresh.
    const r = await fetch("/api/v1/auth/refresh", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (r.ok) {
      const body = await r.json();
      accessToken = body.access || "";
      refreshToken = body.refresh || refreshToken;
      return api(path, opts, false);
    }
    showLogin();
    return res;
  }
  return res;
}

function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (cls) node.className = cls;
  return node;
}

function clear() { while (app.firstChild) app.removeChild(app.firstChild); }

function show(message) {
  let p = app.querySelector("#statusline");
  if (!p) { p = el("p", undefined, "notice"); p.id = "statusline"; app.insertBefore(p, app.firstChild); }
  p.textContent = message;
}

// problem reads the RFC 7807 body and returns the sentence an operator should
// see. A 409 and a 429 carry different advice, so the code is kept.
async function problem(res) {
  const body = await res.json().catch(() => null);
  const e = body && body.error ? body.error : null;
  if (!e) return "The server answered " + res.status + ".";
  if (res.status === 429) return (e.message || "Too many requests.") + " Try again later.";
  if (res.status === 409) return e.message || "The envelope is in a state that does not allow that.";
  if (res.status === 403) return "This account may not do that.";
  return e.message || ("Request failed (" + res.status + ").");
}

function linkTo(path, label, onClick) {
  const a = el("a", label);
  a.href = path;
  a.addEventListener("click", (ev) => { ev.preventDefault(); onClick(); });
  return a;
}

// ---------------------------------------------------------------------------
// login

function showLogin() {
  accessToken = ""; refreshToken = "";
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  clear();
  app.appendChild(el("h1", "Signsrv admin"));
  const form = el("form", undefined, "field");
  form.appendChild(el("label", "Email"));
  const email = el("input"); email.type = "email"; email.setAttribute("autofocus", "");
  form.appendChild(email);
  form.appendChild(el("label", "Password"));
  const pw = el("input"); pw.type = "password";
  form.appendChild(pw);
  const btn = el("button", "Log in", "primary");
  form.appendChild(btn);
  app.appendChild(form);

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const res = await fetch("/api/v1/auth/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email.value.trim(), password: pw.value }),
    });
    if (!res.ok) { show(await problem(res)); return; }
    const body = await res.json();
    accessToken = body.access || "";
    refreshToken = body.refresh || "";
    showDashboard();
  });
  btn.addEventListener("click", () => form.requestSubmit());
}

function shell(title, path) {
  clear();
  app.appendChild(el("h1", title));
  const nav = el("nav", undefined, "nav");
  nav.appendChild(linkTo("/", "Dashboard", showDashboard));
  nav.appendChild(linkTo("/admin/envelopes", "Envelopes", showEnvelopes));
  nav.appendChild(linkTo("/admin/settings", "Settings", showSettings));
  const logoutBtn = el("button", "Log out");
  logoutBtn.addEventListener("click", async () => {
    await api("/admin/logout", { method: "POST" });
    showLogin();
  });
  nav.appendChild(logoutBtn);
  app.appendChild(nav);
  app.appendChild(el("p", undefined, "muted"));
}

// ---------------------------------------------------------------------------
// dashboard

async function showDashboard() {
  shell("Dashboard", "/");
  const res = await api("/admin/stats");
  if (!res.ok) { show(await problem(res)); return; }
  const body = await res.json();

  const grid = el("div", undefined, "grid");
  for (const [status, count] of Object.entries(body.by_status || body.counts || {})) {
    const tile = el("div", undefined, "card");
    tile.appendChild(el("strong", String(count)));
    tile.appendChild(el("p", status, "muted"));
    grid.appendChild(tile);
  }
  app.appendChild(grid);

  const queues = body.queues || {};
  const qcard = el("div", undefined, "card");
  qcard.appendChild(el("h2", "Queues"));
  qcard.appendChild(el("p", "mail waiting " + (queues.mail_waiting ?? 0) +
    ", in flight " + (queues.mail_claimed ?? 0) +
    ", oldest " + (queues.mail_oldest_seconds ?? 0) + "s"));
  qcard.appendChild(el("p", "batch waiting " + (queues.batch_waiting ?? 0) +
    ", in flight " + (queues.batch_claimed ?? 0) +
    ", failures " + (queues.batch_failures ?? 0)));
  app.appendChild(qcard);

  const overdue = (body.overdue || []);
  if (overdue.length) {
    app.appendChild(el("h2", "Overdue"));
    const list = el("ul", undefined, "parties");
    for (const row of overdue) {
      const li = el("li");
      li.textContent = (row.title || row.id) + " — " + row.status + ", expired " + (row.expires_at || "");
      list.appendChild(li);
    }
    app.appendChild(list);
  }

  app.appendChild(el("h2", "Collecting"));
  const collecting = (body.collecting || []);
  if (!collecting.length) {
    app.appendChild(el("p", "No envelope is waiting for signatures.", "muted"));
  } else {
    const list = el("ul", undefined, "parties");
    for (const row of collecting) {
      const li = el("li");
      li.textContent = (row.title || row.id) + " — " + row.consented + "/" + row.total;
      li.appendChild(document.createTextNode(" "));
      li.appendChild(linkTo("/admin/envelopes/" + row.id, "open", () => showEnvelope(row.id)));
      list.appendChild(li);
    }
    app.appendChild(list);
  }

  // Poll every 30s, and only while this tab is visible: a dashboard in a
  // background tab is not being read, and the stats query is not free.
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(() => {
    if (document.visibilityState === "visible") showDashboard();
  }, 30000);
}

// ---------------------------------------------------------------------------
// envelope table

async function showEnvelopes() {
  shell("Envelopes", "/admin/envelopes");
  const res = await api("/envelopes");
  if (!res.ok) { show(await problem(res)); return; }
  const body = await res.json();
  const rows = body.envelopes || [];
  app.appendChild(el("p", rows.length + " envelope(s).", "muted"));
  const table = el("table");
  const head = el("tr");
  for (const h of ["title", "status", "progress", "created", "expires"]) head.appendChild(el("th", h));
  table.appendChild(head);
  for (const row of rows) {
    const tr = el("tr");
    const titleCell = el("td");
    titleCell.appendChild(linkTo("/admin/envelopes/" + row.id, row.title || row.id, () => showEnvelope(row.id)));
    tr.appendChild(titleCell);
    tr.appendChild(el("td", row.status || ""));
    tr.appendChild(el("td", row.consented + "/" + row.parties));
    tr.appendChild(el("td", row.created_at || ""));
    tr.appendChild(el("td", row.expires_at || ""));
    table.appendChild(tr);
  }
  app.appendChild(table);
}

// ---------------------------------------------------------------------------
// envelope detail

async function showEnvelope(id) {
  shell("Envelope", "/admin/envelopes/" + id);
  const res = await api("/envelopes/" + encodeURIComponent(id));
  if (!res.ok) { show(await problem(res)); return; }
  const body = await res.json();
  const env = body.envelope || body;

  app.appendChild(el("h2", env.title || env.id));
  app.appendChild(el("p", "status " + env.status + " · " + (env.consented ?? 0) + "/" + (env.parties ?? 0) +
    " consented · expires " + (env.expires_at || "none")));

  const actions = el("div", undefined, "actions");
  const action = (label, path, method, bodyText) => {
    const b = el("button", label);
    b.addEventListener("click", async () => {
      const r = await api(path, { method: method || "POST", body: bodyText });
      if (!r.ok) { show(await problem(r)); return; }
      show(label + " accepted.");
      showEnvelope(id);
    });
    actions.appendChild(b);
  };
  action("send", "/envelopes/" + encodeURIComponent(id) + "/send");
  action("remind", "/envelopes/" + encodeURIComponent(id) + "/remind");
  action("reissue links", "/envelopes/" + encodeURIComponent(id) + "/reissue");
  action("sign now", "/envelopes/" + encodeURIComponent(id) + "/sign");
  const cancelBtn = el("button", "cancel");
  cancelBtn.addEventListener("click", async () => {
    const reason = window.prompt("Why is this request cancelled?");
    if (!reason) { show("A cancel needs a reason."); return; }
    const r = await api("/envelopes/" + encodeURIComponent(id) + "/cancel",
      { method: "POST", body: JSON.stringify({ reason: reason }) });
    if (!r.ok) { show(await problem(r)); return; }
    show("Cancelled.");
    showEnvelope(id);
  });
  actions.appendChild(cancelBtn);
  const dl = el("a", "download document");
  dl.href = "/api/v1/envelopes/" + encodeURIComponent(id) + "/document";
  dl.setAttribute("rel", "noopener");
  actions.appendChild(dl);
  const zip = el("a", "download audit.zip");
  zip.href = "/api/v1/envelopes/" + encodeURIComponent(id) + "/audit.zip";
  zip.setAttribute("rel", "noopener");
  actions.appendChild(zip);
  app.appendChild(actions);

  const report = await api("/envelopes/" + encodeURIComponent(id) + "/report");
  if (report.ok) {
    const r = await report.json();
    const rep = r.report || {};
    const card = el("div", undefined, "card");
    card.appendChild(el("h2", "Report"));
    card.appendChild(el("p", "document valid: " + String(rep.valid === true) +
      " · signatures: " + (rep.signers ? rep.signers.length : 0) +
      " · party signatures " + (r.signed_parties ?? 0) + "/" + (r.required_parties ?? 0) +
      " · complete: " + String(r.complete === true)));
    if (rep.errors && rep.errors.length) card.appendChild(el("p", rep.errors.join("; "), "muted"));
    app.appendChild(card);
  }

  app.appendChild(el("h2", "Parties"));
  const partyList = el("ul", undefined, "parties");
  for (const p of body.parties || []) {
    const li = el("li");
    li.textContent = p.name + " <" + (p.email || "") + "> — " + (p.status || "") +
      (p.consented_at ? ", consented " + p.consented_at : "") +
      (p.signature ? ", signed \"" + p.signature + "\" at " + (p.signed_at || "") +
        (p.serial ? ", cert " + p.serial : "") : "");
    partyList.appendChild(li);
  }
  app.appendChild(partyList);

  app.appendChild(el("h2", "Revisions"));
  const revList = el("ul", undefined, "parties");
  for (const rev of body.revisions || []) {
    const li = el("li");
    li.textContent = rev.kind + " · " + (rev.sha256 || "").slice(0, 16) + " · " + (rev.created_at || "");
    revList.appendChild(li);
  }
  app.appendChild(revList);

  const events = await api("/admin/events?envelope=" + encodeURIComponent(id));
  if (events.ok) {
    const e = await events.json();
    app.appendChild(el("h2", "Events"));
    const list = el("ul", undefined, "parties");
    for (const ev of e.events || []) {
      const li = el("li");
      li.textContent = (ev.created_at || "") + " " + ev.actor + " " + ev.kind;
      list.appendChild(li);
    }
    app.appendChild(list);
  }
}

// ---------------------------------------------------------------------------
// settings

async function showSettings() {
  shell("Settings", "/admin/settings");
  const res = await api("/admin/settings");
  if (!res.ok) { show(await problem(res)); return; }
  const settings = (await res.json()).settings || {};

  const form = el("form", undefined, "field");
  const fields = {};
  for (const key of ["tsa_url", "link_ttl", "mail_from", "smtp_host"]) {
    form.appendChild(el("label", key));
    const input = el("input");
    input.value = settings[key] || "";
    fields[key] = input;
    form.appendChild(input);
  }
  const save = el("button", "Save", "primary");
  form.appendChild(save);
  app.appendChild(form);

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const changes = {};
    for (const key of Object.keys(fields)) {
      if (fields[key].value !== (settings[key] || "")) changes[key] = fields[key].value;
    }
    if (!Object.keys(changes).length) { show("Nothing changed."); return; }
    const r = await api("/admin/settings", { method: "PATCH", body: JSON.stringify(changes) });
    if (!r.ok) { show(await problem(r)); return; }
    show("Saved " + Object.keys(changes).join(", ") + ".");
    showSettings();
  });

  const clients = await api("/admin/clients");
  if (clients.ok) {
    app.appendChild(el("h2", "Machine clients"));
    const list = el("ul", undefined, "parties");
    for (const c of (await clients.json()).clients || []) {
      const li = el("li");
      li.textContent = c.name + " — " + (c.scopes || []).join(" ") +
        (c.revoked_at ? ", revoked " + c.revoked_at : "");
      const revoke = el("button", "revoke");
      revoke.addEventListener("click", async () => {
        const r = await api("/admin/clients/" + encodeURIComponent(c.id), { method: "DELETE" });
        if (!r.ok) { show(await problem(r)); return; }
        show("Client revoked.");
        showSettings();
      });
      li.appendChild(document.createTextNode(" "));
      li.appendChild(revoke);
      list.appendChild(li);
    }
    app.appendChild(list);
  }

  const add = el("div", undefined, "field");
  add.appendChild(el("label", "New machine client name"));
  const nameInput = el("input");
  add.appendChild(nameInput);
  const scopes = el("div", undefined, "muted");
  scopes.textContent = "envelope:read and envelope:write are the most a client may hold.";
  add.appendChild(scopes);
  const create = el("button", "Create client");
  add.appendChild(create);
  app.appendChild(add);
  create.addEventListener("click", async () => {
    const r = await api("/admin/clients", {
      method: "POST",
      body: JSON.stringify({ name: nameInput.value.trim(), scopes: ["envelope:read", "envelope:write"] }),
    });
    if (!r.ok) { show(await problem(r)); return; }
    const body = await r.json();
    clear();
    app.appendChild(el("h1", "Settings"));
    const pre = el("pre", body.key || "");
    app.appendChild(el("p", "This is the only time it is shown.", "notice"));
    app.appendChild(pre);
    app.appendChild(el("p", "client id " + body.id, "muted"));
  });
}

// ---------------------------------------------------------------------------
// entry point

if (accessToken) { showDashboard(); } else { showLogin(); }
