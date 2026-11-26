// The admin app. Built in step 09 (see docs/steps/09-admin-ui.md), reworked
// when the Clients view was added.
// Rules: token in a JS variable only, never in storage; every server string
// rendered with textContent. No framework, no build step, no third-party JS,
// no external URL: every request is a relative path under /api/v1.
//
// The views are rendered in JS, so navigation is a hash route: back and
// forward work, and a reload lands on the page you were looking at. Reloading
// loses the token by design, so the path is remembered and followed once the
// operator has logged in again.

const app = document.getElementById("app");
const statusline = document.getElementById("statusline");

let accessToken = "";   // in memory only
let refreshToken = "";  // used by exactly one call: refresh
let pendingPath = "";   // the route to follow once logged in
let pollTimer = null;   // dashboard refresh, cancelled by every shell()
let sessionRole = "";    // "admin" or "client", straight from the login answer
let sessionScopes = [];  // what this session may call; a client holds envelope scopes only

// ---------------------------------------------------------------- api layer

// REQUEST_TIMEOUT is the ceiling on one call. Without it a request that hangs
// (a proxy that accepts and never answers) leaves the page showing a spinner
// forever, and the operator cannot tell a slow server from a dead one.
const REQUEST_TIMEOUT = 20000;

async function rawFetch(path, opts) {
  const o = Object.assign({ credentials: "same-origin" }, opts || {});
  o.headers = Object.assign({ "Content-Type": "application/json" }, o.headers || {});
  const ctl = new AbortController();
  o.signal = ctl.signal;
  const timer = setTimeout(() => ctl.abort(), REQUEST_TIMEOUT);
  try {
    return await fetch("/api/v1" + path, o);
  } finally {
    clearTimeout(timer);
  }
}

async function api(path, opts) {
  const withToken = Object.assign({}, opts || {});
  if (accessToken) {
    withToken.headers = Object.assign({}, withToken.headers,
      { "Authorization": "Bearer " + accessToken });
  }
  let res = await rawFetch(path, withToken);
  if (res.status === 401 && refreshToken) {
    // Expired. Refresh, then retry once. Both tokens go: refresh rotates the
    // pair, and the access token in hand is revoked so the old one cannot
    // outlive the rotation.
    const r = await rawFetch("/auth/refresh", {
      method: "POST",
      body: JSON.stringify({ refresh: refreshToken, access: accessToken }),
    });
    if (r.ok) {
      const body = await r.json();
      accessToken = body.access;
      refreshToken = body.refresh;
      withToken.headers["Authorization"] = "Bearer " + accessToken;
      res = await rawFetch(path, withToken);
    } else {
      accessToken = "";
      refreshToken = "";
      showLogin("The session expired. Log in again.");
    }
  }
  return res;
}

async function problem(res) {
  try {
    const body = await res.json();
    // Every error from this service is one document:
    // {"error":{"code":...,"message":...,"hint":...}}. The code and the hint
    // are shown alongside the message: the code is what an operator quotes in
    // a support thread, the hint says what to do next. A body that is not that
    // shape (a proxy error page, say) still gets the status line.
    const p = (body && body.error) || body || {};
    let out = p.message || p.detail || p.title || res.status + " " + res.statusText;
    if (p.code && p.code !== "invalid_request") out += " (" + p.code + ")";
    if (p.hint) out += " — " + p.hint;
    return out;
  } catch (_) {
    return res.status + " " + res.statusText;
  }
}

async function getJSON(path) {
  const r = await api(path);
  if (!r.ok) throw new Error(await problem(r));
  return r.json();
}

// The event payload on one line: the audit list is a table of rows, and a
// pretty-printed payload turns it into a wall of braces.
function logJSON(o) {
  // The detail endpoint sends a payload as a JSON string, the audit endpoint
  // as JSON. Parse the first so both render as one readable line instead of a
  // quoted, escaped wall.
  if (typeof o === "string") {
    try { o = JSON.parse(o); } catch (_) { return o; }
  }
  try { return JSON.stringify(o); } catch (_) { return String(o); }
}

// ------------------------------------------------------------- element maker

function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (cls) node.className = cls;
  return node;
}

function card(title, lede) {
  const c = el("div", undefined, "card");
  if (title) c.appendChild(el("h2", title));
  if (lede) c.appendChild(el("p", lede, "lede"));
  return c;
}

function clear() {
  // A result dialog belongs to the view that fetched it, and it is modal: a
  // route away from that view takes it down rather than leaving a dialog
  // floating over a page that has just been replaced.
  closeResultDialog();
  // The notice lives inside the page so it reads in order, which means a
  // re-render would take it down with the rest. Park it on the body first: an
  // action that shows a message and then reloads the view still has somewhere
  // to show it.
  if (statusline && statusline.parentNode !== document.body) {
    document.body.appendChild(statusline);
  }
  while (app.firstChild) app.removeChild(app.firstChild);
}

// Status line: a success or a failure, never a server's raw HTML.
function show(msg, kind) {
  if (!statusline) return;
  statusline.textContent = msg || "";
  statusline.className = "notice " + (kind || "");
  statusline.hidden = !msg;
  if (!msg) return;
  // The notice belongs under the page head, where the operator's eye already
  // is. A view with no head (the login card) gets it at the top of the body.
  // A view with no head (the login card) gets it at the top of the body, so
  // a failure on the login form is never thrown away — and never crashes:
  // #page is absent until shell() builds a page, which is exactly when show()
  // is called from a failed login.
  const page = document.getElementById("page");
  if (page && page.childNodes.length > 1) {
    page.insertBefore(statusline, page.childNodes[1]);
  } else if (!page || !page.contains(statusline)) {
    document.body.insertBefore(statusline, document.body.firstChild);
  }
}

// A destructive action asks first. A browser confirm() is enough here and is
// one less widget to get wrong.
function confirmRun(text, fn) {
  return async function () {
    if (!window.confirm(text)) return;
    try { await fn(); } catch (err) { show(String(err.message || err), "bad"); }
  };
}

function button(label, cls, onClick) {
  const b = el("button", label, cls);
  b.type = "button";
  if (onClick) b.addEventListener("click", onClick);
  return b;
}

// The result dialog. There is one at a time, held here so the next one can
// take the first one down; a dialog nobody has a reference to cannot be closed.
let resultDialog = null;
let resultURL = "";      // the blob URL the open dialog points at
let resultSeq = 0;       // just so each dialog's heading has its own id

// Take the dialog out of the document and free the bytes behind its URL.
// revokeObjectURL matters: a removed element whose URL is still alive keeps
// the whole document (a signed PDF, a whole audit archive) in memory.
function dropResultDialog() {
  if (resultURL) { URL.revokeObjectURL(resultURL); resultURL = ""; }
  if (resultDialog) { resultDialog.remove(); resultDialog = null; }
}

// Closing is synchronous here on purpose. close() queues its "close" event
// rather than firing it, so a replacement that waits for the event would have
// the queued teardown take down the *new* dialog. The event listener is still
// there for Esc, and it checks it is closing the dialog it was attached to.
function closeResultDialog() {
  const dl = resultDialog;
  if (!dl) return;
  if (dl.open) dl.close();
  dropResultDialog();
}

// A zip and a PDF are hundreds of kilobytes, and "178813 bytes" makes the
// operator count zeroes to find out how big.
function sizeText(n) {
  if (n === undefined || n === null) return "";
  if (n < 1024) return n + " bytes";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(2) + " MB";
}

// The name to save as. The server names the file on /document and /audit.zip
// through Content-Disposition, and its name is the better one: it carries the
// envelope id and the extension. /report sends no filename, so the last path
// segment and the media type's extension are what the operator gets.
function saveName(path, res, blob) {
  const cd = res.headers.get("Content-Disposition") || "";
  const m = /filename="?([^";]+)"?/.exec(cd);
  if (m) return m[1];
  const name = path.split("/").pop() || "download";
  if (name.indexOf(".") >= 0) return name;
  const type = (blob && blob.type) || "";
  if (type.indexOf("json") >= 0) return name + ".json";
  if (type.indexOf("pdf") >= 0) return name + ".pdf";
  if (type.indexOf("zip") >= 0) return name + ".zip";
  return name;
}

// Present what a fetch brought back. The modal is the point: the notice strip
// sits at the top of the page and a slow archive is ready after the operator
// has scrolled past it, so the answer has to come to them.
//
// The heading is the label the operator clicked, so the box says which click
// answered — they may have clicked two of the three before the first arrived.
function showResultDialog(title, path, name, blob) {
  closeResultDialog();   // one at a time: this replaced the last one
  resultURL = URL.createObjectURL(blob);
  const dl = el("dialog", undefined, "result");
  const heading = el("h2", title);
  // The labels repeat when the same link is clicked twice, and a labelled-by
  // pointing at a stale id names the wrong box, so each dialog gets its own.
  heading.id = "result-title-" + (++resultSeq);
  dl.setAttribute("aria-labelledby", heading.id);
  dl.appendChild(heading);
  dl.appendChild(el("p", "Ready to open or save. This box replaced any other one that was open. Press Esc, or click outside it, to close it.", "lede"));
  // The name, the size and the path it came from: the operator is about to
  // save a file and needs all three to know they are saving the right one.
  dl.appendChild(el("p", name + " · " + sizeText(blob.size) + " · /api/v1" + path, "meta"));
  const row = el("div", undefined, "actions");
  const open = el("a", "Open " + name);
  open.href = resultURL; open.target = "_blank"; open.rel = "noopener";
  const save = el("a", "Save " + name);
  save.href = resultURL; save.download = name;
  row.appendChild(open); row.appendChild(save);
  row.appendChild(button("Close", "close", () => closeResultDialog()));
  dl.appendChild(row);
  // A click outside the panel, and Esc, are both "I have it, put it away".
  // The panel fills the dialog box, so the only thing that can be the target
  // is the backdrop.
  dl.addEventListener("click", (ev) => { if (ev.target === dl) closeResultDialog(); });
  dl.addEventListener("close", () => { if (resultDialog === dl) dropResultDialog(); });
  // Register before opening: the "close" listener below compares against this,
  // and without the assignment there is no open dialog to replace — which is
  // how dialogs end up stacked two deep again.
  resultDialog = dl;
  document.body.appendChild(dl);
  // showModal is what puts it over the page and makes Esc and the backdrop
  // belong to it. On a browser without it the dialog still opens in place.
  if (typeof dl.showModal === "function") dl.showModal(); else dl.setAttribute("open", "");
}

// A link straight at an API path. The token is in memory, so a bare href
// would download an unauthorized body; these go through fetch and offer the
// result as a blob instead.
//
// Three of them live on the envelope page — /document, /report, /audit.zip —
// and none of the three is a read of a file sitting on disk: /audit.zip
// assembles the archive and /report re-verifies the signatures on every click,
// so the answer arrives some seconds after the click. Two things follow.
//
// The control says it is working, because a link that changes nothing while
// the server works looks exactly like a link that does nothing.
//
// And the answer goes into the dialog, once. The first version spliced a fresh
// "Open/Save" row into the page on every click and never removed one, so the
// click that "did nothing" had in fact added a row at the top of the page, and
// an operator trying three times got three rows and an archive to hunt for.
// Clicking again now replaces the open dialog rather than stacking a copy, so
// any number of clicks leaves exactly one thing on screen to deal with.
function apiLink(path, label) {
  const a = el("a", label);
  a.href = "#";
  a.addEventListener("click", async (ev) => {
    ev.preventDefault();
    if (a.classList.contains("busy")) return;   // this control is already fetching
    const was = a.textContent;
    a.classList.add("busy");
    a.textContent = "Fetching…";
    try {
      const r = await api(path);
      if (!r.ok) { show(await problem(r), "bad"); return; }
      const blob = await r.blob();
      show("", "");   // a stale notice behind the dialog is noise
      showResultDialog(label, path, saveName(path, r, blob), blob);
    } catch (err) {
      show(String(err.message || err), "bad");
    } finally {
      a.classList.remove("busy");
      a.textContent = was;
    }
  });
  return a;
}

function linkTo(path, label, onClick) {
  const a = el("a", label);
  a.href = "#" + path;
  if (onClick) a.addEventListener("click", (ev) => { ev.preventDefault(); onClick(); });
  return a;
}

// A copy control. The key is shown once, so being able to select it is not
// enough: without this an operator retypes a 32-character hex string.
function copyButton(text) {
  const b = button("Copy", "mini", async () => {
    try {
      if (navigator.clipboard) {
        await navigator.clipboard.writeText(text);
        b.textContent = "Copied";
        setTimeout(() => { b.textContent = "Copy"; }, 1500);
        return;
      }
    } catch (_) { /* fall through to the manual hint */ }
    show("Copy manually: select the text above.", "warn");
  });
  return b;
}

// ------------------------------------------------------------- shell and nav

// The shell is the frame every view is drawn inside: top bar, nav, page head.
// It takes two arguments by design — the header's second line is optional, so
// it is read from arguments rather than widening the signature every view has
// to satisfy.
function shell(title, path) {
  const subtitle = arguments[2];
  clearInterval(pollTimer);   // every view owns its own timer, if any
  clear();
  const top = el("header", undefined, "top");
  const bar = el("div", undefined, "bar");
  const brand = el("div", undefined, "brand");
  brand.appendChild(el("b", "signsrv"));
  brand.appendChild(el("span", sessionRole === "client" ? "client" : "admin"));
  bar.appendChild(brand);
  const nav = el("nav", undefined, "nav");
  // A client session holds envelope scopes only, so the operator views are not
  // offered: they would fetch /admin/* and answer 403.
  const links = [["/", "Dashboard"], ["/admin/envelopes", "Envelopes"]];
  if (sessionRole !== "client") links.push(["/admin/clients", "Clients"], ["/admin/settings", "Settings"]);
  for (const [p, label] of links) {
    const a = el("a", label);
    a.href = "#" + p;
    if (p === path) a.setAttribute("aria-current", "page");
    if (p === path) a.addEventListener("click", (ev) => { ev.preventDefault(); route(true); });
    nav.appendChild(a);
  }
  nav.appendChild(button("Refresh", "", () => route(true)));
  const out = button("Log out", "", async () => {
    try {
      await api("/auth/logout", { method: "POST", body: JSON.stringify({ refresh: refreshToken }) });
    } catch (_) { /* the tokens are dropped either way */ }
    accessToken = ""; refreshToken = "";
    showLogin("Logged out.");
  });
  nav.appendChild(out);
  bar.appendChild(nav);
  top.appendChild(bar);
  app.appendChild(top);

  const main = el("div");
  main.id = "page";
  const head = el("div", undefined, "head");
  const block = el("div");
  block.appendChild(el("h1", title));
  if (subtitle) block.appendChild(el("p", subtitle, "sub"));
  head.appendChild(block);
  main.appendChild(head);
  app.appendChild(main);
  return main;
}

// ------------------------------------------------------------------- router

// "admin" marks a view whose data lives behind ScopeAdminRead; a client
// session cannot read it, so the route is refused rather than rendered empty.
const routes = [
  { path: "/", view: () => (sessionRole === "client" ? showClientDashboard() : showDashboard()) },
  { path: "/admin/envelopes", view: () => showEnvelopeList() },
  { path: "/admin/clients", view: showClients, admin: true },
  { path: "/admin/settings", view: showSettings, admin: true },
];

function routeAllows(path) {
  for (const r of routes) {
    if (path === r.path) return !r.admin || sessionRole !== "client";
  }
  if (path.indexOf("/admin/envelopes/") === 0) return true;
  return false;
}

let view = "/";

function currentPath() {
  const h = location.hash.replace(/^#/, "");
  return h || "/";
}

function route(force) {
  if (!accessToken) { pendingPath = currentPath(); showLogin(); return; }
  const path = currentPath();
  if (!force && path === view) { route(true); return; }
  for (const r of routes) {
    if (path === r.path) {
      if (r.admin && sessionRole === "client") {
        view = "/";
        showClientDashboard();
        show("This session is a machine client. The operator views read /admin/*, which needs the admin scope.", "bad");
        return;
      }
      view = path;
      r.view();
      return;
    }
  }
  if (path.indexOf("/admin/envelopes/") === 0) {
    view = path;
    showEnvelopeDetail(path.slice("/admin/envelopes/".length));
    return;
  }
  view = path;
  showDashboard();
}

window.addEventListener("hashchange", () => route(false));

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && view === "/" && accessToken) {
    showDashboard();
  }
});

// -------------------------------------------------------------------- login

// Two credentials reach this service, and they go to different endpoints:
// an admin's email and password go to /auth/login, a machine client's key
// goes to /auth/token. The dashboard used to offer only the first, so a
// client key typed into the password box got a 401 whose failure then threw
// inside show() (see the null #page guard there).
//
// A client session cannot hold admin scopes — admin.go only ever grants a
// client envelope:read and envelope:write — so a client logs into a view of
// its own envelopes, not the operator console.

let loginMode = "password";

// The key is the secret (db.go: "key_" + 32 random bytes, hex). A client's id
// is a short number and its name is plain text, so anything that does not look
// like the secret is reported as the thing the operator probably typed.
const KEY_SHAPE = /^key_[0-9a-f]{64}$/;

function loginHint(mode, cred) {
  if (mode !== "key") return "";
  const c = cred.trim();
  if (c === "") return " — a client key looks like key_<64 hex>";
  if (KEY_SHAPE.test(c)) return "";
  if (c.indexOf("key_") === 0) {
    return " — \"" + c + "\" starts like a key but is not one: after key_ it is "
      + c.slice(4).length + " characters of hex, and it needs 64";
  }
  return " — \"" + c + "\" looks like a client id or name; /auth/token takes the key itself, not the id";
}
function showLogin(message) {
  clear();
  clearInterval(pollTimer);
  accessToken = "";
  refreshToken = "";
  sessionRole = "";
  sessionScopes = [];
  const box = el("div", undefined, "card");
  box.style.maxWidth = "26rem";
  box.style.margin = "3rem auto";
  box.appendChild(el("h1", "signsrv admin"));
  box.appendChild(el("p", "Administrator email and password, or a machine client key.", "muted small"));
  if (message) box.appendChild(el("p", message, "notice bad"));

  const mode = el("select");
  for (const opt of [["password", "Email and password"], ["key", "Client key"]]) {
    const o = el("option", opt[1]);
    o.value = opt[0];
    if (loginMode === opt[0]) o.selected = true;
    mode.appendChild(o);
  }
  const email = el("input"); email.type = "email"; email.autocomplete = "username";
  const pw = el("input"); pw.type = "password"; pw.autocomplete = "current-password";
  const cred = el("input"); cred.type = "text"; cred.autocomplete = "off";
  cred.placeholder = "key_<64 hex>";
  const f0 = el("label", "Credential", "field"); f0.appendChild(mode);
  const f1 = el("label", "Email", "field"); f1.appendChild(email);
  const f2 = el("label", "Password", "field"); f2.appendChild(pw);
  const f3 = el("label", "Client key", "field"); f3.appendChild(cred);
  box.appendChild(f0); box.appendChild(f1); box.appendChild(f2); box.appendChild(f3);

  // Exactly one pair is in the layout, in the tab order, and eligible for
  // submit, so a key is never typed into the password box (which is how this
  // failure was reached in the first place).
  //
  // hidden is the state; disabled is set alongside it rather than instead of
  // it. A disabled input is skipped by the keyboard and ignored by a form
  // submission, so the pair that is not in play cannot be reached by Tab or
  // read back by anything that collects the form later. And hidden only
  // removes the row while the stylesheet agrees: the [hidden] rule in app.css
  // exists because .field sets display:block, which outranks the UA sheet's
  // [hidden] rule, and without it the two greyed-out boxes stayed on screen
  // and the operator saw a form asking for three credentials at once.
  function applyMode() {
    loginMode = mode.value;
    const key = loginMode === "key";
    for (const f of [f1, f2]) f.hidden = key;
    f3.hidden = !key;
    email.disabled = key;
    pw.disabled = key;
    cred.disabled = !key;
    (key ? cred : email).focus();
  }
  mode.addEventListener("change", applyMode);
  applyMode();

  const go = button("Log in", "primary", submit);
  box.appendChild(go);
  app.appendChild(box);
  cred.addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });
  pw.addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });

  async function submit() {
    go.disabled = true;
    const key = loginMode === "key";
    try {
      const res = await rawFetch(key ? "/auth/token" : "/auth/login", {
        method: "POST",
        body: JSON.stringify(key
          ? { key: cred.value.trim() }
          : { email: email.value.trim(), password: pw.value }),
      });
      if (!res.ok) {
        show(await problem(res) + loginHint(loginMode, key ? cred.value : email.value), "bad");
        go.disabled = false;
        return;
      }
      const body = await res.json();
      accessToken = body.access;
      refreshToken = body.refresh;
      sessionRole = body.role || (key ? "client" : "admin");
      sessionScopes = body.scopes || [];
      let path = pendingPath; pendingPath = "";
      if (path && path !== "/" && !routeAllows(path)) path = "/";
      if (path && path !== "/") location.hash = "#" + path;
      route(true);
    } catch (err) {
      show(String(err.message || err), "bad");
      go.disabled = false;
    }
  }
}

// ---------------------------------------------------------------- dashboard

const STATUS_ORDER = ["draft", "ready", "sent", "collecting", "signed",
  "completed", "delivered", "expired", "cancelled", "failed"];

function badge(status) {
  return el("span", status, "badge " + status);
}

// A time from the server is UTC RFC 3339 with seconds. Shown in the browser's
// zone, because an operator reading "14:02Z" has to do arithmetic to know
// whether that was before lunch.
function whenText(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

async function showDashboard() {
  const main = shell("Dashboard", "/", "Live state of this instance. Polls every 30 seconds.");
  let body;
  try {
    body = await getJSON("/admin/stats");
  } catch (err) {
    main.appendChild(el("p", String(err.message || err), "notice bad"));
    return;
  }
  show("");

  const counts = body.by_status || body.counts || {};
  const grid = el("div", undefined, "grid");
  const live = ["sent", "collecting", "signed"].reduce((n, k) => n + (counts[k] || 0), 0);
  const tile = (label, n, cls) => {
    const t = el("div", undefined, "tile " + (cls || ""));
    t.appendChild(el("strong", n));
    t.appendChild(el("span", label, "cap"));
    return t;
  };
  grid.appendChild(tile("awaiting a signer", live, live ? "live" : "zero"));
  grid.appendChild(tile("overdue", body.overdue || 0, body.overdue ? "warn" : "zero"));
  for (const st of STATUS_ORDER) {
    grid.appendChild(tile(st, counts[st] || 0, counts[st] ? "" : "zero"));
  }
  // The queue depth is what tells an operator the worker is not draining. The
  // waiting count alone is not enough: a queue that is claimed but never
  // finished shows as zero waiting and a non-zero claimed.
  const q = body.queues || {};
  grid.appendChild(tile("mail waiting", q.mail_waiting || 0, q.mail_waiting ? "warn" : "zero"));
  grid.appendChild(tile("mail in flight", q.mail_claimed || 0, q.mail_claimed ? "warn" : "zero"));
  grid.appendChild(tile("batches waiting", q.batch_waiting || 0, q.batch_waiting ? "warn" : "zero"));
  grid.appendChild(tile("batch failures", q.batch_failures || 0, q.batch_failures ? "warn" : "zero"));
  if (q.mail_oldest_seconds) {
    grid.appendChild(tile("oldest mail (min)", Math.round(q.mail_oldest_seconds / 60), "warn"));
  }
  main.appendChild(grid);

  const collecting = body.collecting || [];
  const c = card("Collecting", "Envelopes with at least one consent in.");
  if (!collecting.length) {
    c.appendChild(el("p", "Nothing is collecting.", "muted"));
  } else {
    const t = el("table");
    const head = el("tr");
    for (const h of ["Envelope", "Progress", ""]) {
      head.appendChild(el("th", h, h === "Progress" ? "num" : ""));
    }
    t.appendChild(head);
    for (const row of collecting) {
      const tr = el("tr");
      const td = el("td");
      td.appendChild(linkTo("/admin/envelopes/" + row.id, row.title || row.id));
      td.appendChild(el("div", row.id, "id"));
      tr.appendChild(td);
      const tp = el("td", undefined, "num");
      const total = row.total || 0;
      const pct = total ? Math.round(100 * (row.consented || 0) / total) : 0;
      const pr = el("span", undefined, "progress" + (total && row.consented >= total ? " done" : ""));
      const track = el("span", undefined, "track");
      const fill = el("span", undefined, "fill");
      fill.style.width = pct + "%";
      track.appendChild(fill);
      pr.appendChild(track);
      pr.appendChild(el("span", (row.consented || 0) + " of " + total));
      tp.appendChild(pr);
      tr.appendChild(tp);
      const ta = el("td", undefined, "num");
      ta.appendChild(linkTo("/admin/envelopes/" + row.id, "Open", "mini"));
      tr.appendChild(ta);
      t.appendChild(tr);
    }
    c.appendChild(t);
  }
  main.appendChild(c);

  const e = card("Recent events", "The audit log, newest first.");
  try {
    const ev = await getJSON("/admin/events?limit=20");
    e.appendChild(eventList(ev.events || []));
  } catch (err) {
    e.appendChild(el("p", String(err.message || err), "muted"));
  }
  main.appendChild(e);

  // Poll. The guard keeps a backgrounded tab from burning requests.
  pollTimer = setInterval(() => {
    if (view === "/" && accessToken && document.visibilityState === "visible") {
      showDashboard();
    }
  }, 30000);
}

function eventList(events) {
  const ul = el("ul", undefined, "log");
  if (!events.length) {
    ul.appendChild(el("li", "No events yet."));
    return ul;
  }
  for (const ev of events) {
    const li = el("li");
    li.appendChild(el("time", whenText(ev.created_at)));
    li.appendChild(el("span", ev.kind, "kind"));
    const who = el("span", undefined, "who");
    who.textContent = (ev.actor || "system") + " · " + logJSON(ev.payload || {});
    li.appendChild(who);
    ul.appendChild(li);
  }
  return ul;
}

// ---------------------------------------------------------------- envelopes

let envelopeFilter = { status: "", q: "" };

async function showEnvelopeList() {
  const main = shell("Envelopes", "/admin/envelopes", "Every envelope this instance has, newest first.");
  const bar = el("div", undefined, "form-inline");
  const fs = el("label", "Status", "field");
  const sel = el("select");
  for (const opt of [["", "any"], ["draft", "draft"], ["ready", "ready"], ["sent", "sent"],
    ["collecting", "collecting"], ["signed", "signed"], ["completed", "completed"],
    ["delivered", "delivered"], ["expired", "expired"], ["cancelled", "cancelled"],
    ["failed", "failed"]]) {
    const o = el("option", opt[1]);
    o.value = opt[0];
    if (envelopeFilter.status === opt[0]) o.selected = true;
    sel.appendChild(o);
  }
  sel.addEventListener("change", () => { envelopeFilter.status = sel.value; showEnvelopeList(); });
  fs.appendChild(sel);

  const fq = el("label", "Search", "field");
  const qi = el("input"); qi.type = "text"; qi.value = envelopeFilter.q;
  qi.placeholder = "id, title or party email";
  qi.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") { envelopeFilter.q = qi.value.trim(); showEnvelopeList(); }
  });
  fq.appendChild(qi);
  bar.appendChild(fs); bar.appendChild(fq);
  bar.appendChild(button("Search", "primary", () => {
    envelopeFilter.q = qi.value.trim(); showEnvelopeList();
  }));
  main.appendChild(bar);

  const params = new URLSearchParams();
  if (envelopeFilter.status) params.set("status", envelopeFilter.status);
  if (envelopeFilter.q) params.set("q", envelopeFilter.q);
  params.set("limit", "100");
  let body;
  try {
    body = await getJSON("/envelopes?" + params.toString());
  } catch (err) {
    main.appendChild(el("p", String(err.message || err), "notice bad"));
    return;
  }
  show("");
  main.appendChild(envelopeTable(body));
}

// The list table, shared by the operator view and the client view. The detail
// link is /admin/envelopes/<id> for both: a client token reads the envelope
// itself through /envelopes/<id>, which needs envelope:read rather than the
// admin scope the search endpoint behind this table does not restrict.
function envelopeTable(body) {
  const rows = body.envelopes || [];
  const c = card(undefined, undefined);
  c.classList.add("flush");
  if (!rows.length) {
    c.appendChild(el("p", "No envelopes match.", "empty"));
  } else {
    const t = el("table");
    const head = el("tr");
    for (const h of ["Envelope", "Status", "Created", "Updated", "Expires"]) {
      head.appendChild(el("th", h));
    }
    t.appendChild(head);
    for (const env of rows) {
      const tr = el("tr");
      const td = el("td");
      td.appendChild(linkTo("/admin/envelopes/" + env.id, env.title || "(untitled)"));
      td.appendChild(el("div", env.id, "id"));
      tr.appendChild(td);
      const ts = el("td");
      ts.appendChild(badge(env.status));
      tr.appendChild(ts);
      tr.appendChild(el("td", whenText(env.created_at)));
      tr.appendChild(el("td", whenText(env.updated_at)));
      tr.appendChild(el("td", whenText(env.expires_at)));
      t.appendChild(tr);
    }
    c.appendChild(t);
  }
  c.appendChild(el("p", rows.length + " shown of " + (body.total === undefined
    ? rows.length : body.total) + " matching.", "muted small"));
  return c;
}

// A machine client sees its own envelopes and nothing else. /envelopes is
// scoped by the caller in the handler, so this is the whole surface a client
// session can reach — no stats, no clients, no settings.
async function showClientDashboard() {
  const main = shell("Dashboard", "/", "Envelopes this client created.");
  let body;
  try {
    body = await getJSON("/envelopes?limit=100");
  } catch (err) {
    main.appendChild(el("p", String(err.message || err), "notice bad"));
    return;
  }
  show("");
  main.appendChild(envelopeTable(body));
  if (sessionScopes.length) {
    main.appendChild(el("p", "Scopes this session holds: " + sessionScopes.join(", "), "muted small"));
  }
}

// ------------------------------------------------------------ envelope view

async function showEnvelopeDetail(id) {
  const main = shell("Envelope " + id, "/admin/envelopes", "One envelope: its parties, revisions, audit trail, and the operator actions.");
  let body;
  try {
    body = await getJSON("/envelopes/" + encodeURIComponent(id));
  } catch (err) {
    main.appendChild(el("p", String(err.message || err), "notice bad"));
    return;
  }
  show("");
  // This endpoint answers with the envelope's own fields at the top level,
  // alongside parties/revisions/events — not nested under "envelope".
  const env = body;

  const head = card();
  const line = el("div", undefined, "titlerow");
  line.appendChild(el("h2", env.title || "(untitled)"));
  line.appendChild(badge(env.status || "unknown"));
  line.appendChild(el("span", env.id, "id"));
  head.appendChild(line);
  // Only the keys this response actually carries. The audit trail below has
  // the timestamps; inventing a row that renders "—" for a field the endpoint
  // never sends is how an operator starts distrusting the whole page.
  const kv = el("dl", undefined, "kv");
  const put = (k, v) => {
    if (v === undefined || v === null || v === "") return;
    kv.appendChild(el("dt", k));
    kv.appendChild(el("dd", String(v)));
  };
  put("Expires", whenText(env.expires_at));
  put("Consents", env.total !== undefined ? ((env.consented || 0) + " of " + env.total) : undefined);
  put("Cert serial", env.serial);
  put("Document SHA-256", env.document_sha);
  head.appendChild(kv);
  main.appendChild(head);

  const ops = el("div", undefined, "actions");
  ops.appendChild(apiLink("/envelopes/" + env.id + "/document", "Download document"));
  ops.appendChild(apiLink("/envelopes/" + env.id + "/report", "Verify report"));
  ops.appendChild(apiLink("/envelopes/" + env.id + "/audit.zip", "Audit zip"));
  ops.appendChild(el("span", undefined, "sep"));
  const st = env.status;
  const post = async (path, bodyText, ok) => {
    const r = await api(path, { method: "POST", body: bodyText || "{}" });
    if (!r.ok) { show(await problem(r), "bad"); return; }
    show(ok || "Done.", "ok");
    showEnvelopeDetail(id);
  };
  if (st === "draft" || st === "ready") {
    ops.appendChild(button("Send", "primary", () =>
      post("/envelopes/" + env.id + "/send", "{}", "Sent: the invitations are queued.")));
  }
  if (st === "sent" || st === "collecting" || st === "expired") {
    ops.appendChild(button("Reissue", "", () =>
      post("/envelopes/" + env.id + "/reissue", "{}", "Links reissued.")));
    if (st !== "expired") {
      ops.appendChild(button("Remind", "", () =>
        post("/envelopes/" + env.id + "/remind", "{}", "Reminder queued.")));
    }
  }
  if (st === "collecting" || st === "signed") {
    // Sign enqueues the batch. From collecting it needs every consent; from
    // signed it is the repair for a batch that died mid-run.
    ops.appendChild(button("Sign", "primary", () =>
      post("/envelopes/" + env.id + "/sign", "{}", "Batch queued.")));
  }
  if (st !== "delivered" && st !== "cancelled" && st !== "expired" && st !== "failed") {
    ops.appendChild(button("Cancel", "danger", confirmRun("Cancel this envelope? The parties are notified.", async () => {
      const reason = window.prompt("Reason for cancelling (required)", "operator cancelled");
      if (reason === null) return;
      const r = await api("/envelopes/" + env.id + "/cancel", {
        method: "POST", body: JSON.stringify({ reason: reason || "operator cancelled" }),
      });
      if (!r.ok) { show(await problem(r), "bad"); return; }
      show("Cancelled.", "ok");
      showEnvelopeDetail(id);
    })));
  }
  main.appendChild(ops);

  const p = card("Parties", "In signing order. A link token is never shown here; only its state.");
  const pt = el("table");
  const ph = el("tr");
  for (const h of ["#", "Name", "Email", "Status", "Consent at", "Link expires"]) {
    ph.appendChild(el("th", h));
  }
  pt.appendChild(ph);
  for (const party of (body.parties || [])) {
    const tr = el("tr");
    tr.appendChild(el("td", String(party.order)));
    tr.appendChild(el("td", party.name || "—"));
    tr.appendChild(el("td", party.email));
    const ts = el("td");
    ts.appendChild(badge(party.status || "pending"));
    if (party.signature_text) ts.appendChild(el("span", party.signature_text, "muted small"));
    tr.appendChild(ts);
    tr.appendChild(el("td", whenText(party.consent_at)));
    tr.appendChild(el("td", whenText(party.link_expires_at)));
    pt.appendChild(tr);
  }
  if (!(body.parties || []).length) {
    const tr = el("tr");
    tr.appendChild(el("td", "No parties.", "empty"));
    pt.appendChild(tr);
  }
  p.appendChild(pt);
  main.appendChild(p);

  const r = card("Revisions", "The certification chain. The report link verifies the bytes.");
  const rt = el("table");
  const rh = el("tr");
  for (const h of ["#", "Kind", "SHA-256", "Bytes", "Created", "Cert serial"]) {
    rh.appendChild(el("th", h));
  }
  rt.appendChild(rh);
  (body.revisions || []).forEach((rev, i) => {
    const tr = el("tr");
    tr.appendChild(el("td", String(i + 1)));
    tr.appendChild(el("td", rev.kind || "—"));
    const ts = el("td", rev.sha256, "id");
    if (rev.prev_id) ts.appendChild(el("div", "prev " + rev.prev_id.slice(0, 12)));
    tr.appendChild(ts);
    tr.appendChild(el("td", rev.size === undefined ? "—" : String(rev.size), "num"));
    tr.appendChild(el("td", whenText(rev.created_at)));
    tr.appendChild(el("td", rev.cert_serial || "—", "id"));
    rt.appendChild(tr);
  });
  if (!(body.revisions || []).length) {
    rt.appendChild(el("tr")).appendChild(el("td", "No revisions.", "empty"));
  }
  r.appendChild(rt);
  main.appendChild(r);

  const e = card("Events", "Every state change, newest first.");
  e.appendChild(eventList(body.events || []));
  main.appendChild(e);
}

// ------------------------------------------------------------------ clients

async function showClients() {
  const main = shell("Clients", "/admin/clients",
    "Machine callers. A client authenticates with its key and gets a token; the key is shown once, at creation.");
  let body;
  try {
    body = await getJSON("/admin/clients");
  } catch (err) {
    main.appendChild(el("p", String(err.message || err), "notice bad"));
    return;
  }
  show("");
  const clients = body.clients || [];

  const c = card("Existing clients",
    "The id is what you quote when you revoke a client; a revoked client drops off this list. The key is stored as a hash, so it is not recoverable from here.");
  if (!clients.length) {
    c.appendChild(el("p", "No clients yet. Create one below.", "empty"));
  } else {
    const t = el("table");
    const th = el("tr");
    for (const h of ["Client id", "Subject", "Name", "Scopes", "Created", ""]) {
      th.appendChild(el("th", h));
    }
    t.appendChild(th);
    for (const cl of clients) {
      const tr = el("tr");
      tr.appendChild(el("td", String(cl.id), "id"));
      // The subject is what appears in the audit log as the actor of every
      // request this client made, so it is the string an operator needs.
      tr.appendChild(el("td", "client:" + cl.id, "id"));
      tr.appendChild(el("td", cl.name));
      const tsc = el("td");
      for (const s of (cl.scopes || [])) tsc.appendChild(el("span", s, "badge"));
      tr.appendChild(tsc);
      tr.appendChild(el("td", whenText(cl.created_at)));
      const ta = el("td", undefined, "num");
      ta.appendChild(button("Revoke", "mini danger", confirmRun(
        "Revoke client " + cl.id + " (" + cl.name + ")? Its key stops working immediately.",
        async () => {
          const r = await api("/admin/clients/" + encodeURIComponent(cl.id), { method: "DELETE" });
          if (!r.ok) { show(await problem(r), "bad"); return; }
          // Re-render first, then say so: every view clears the notice when it
          // draws, so a message shown before the redraw would be erased by it.
          await showClients();
          show("Client " + cl.id + " (" + cl.name + ") revoked.", "ok");
        })));
      tr.appendChild(ta);
      t.appendChild(tr);
    }
    c.appendChild(t);
  }
  main.appendChild(c);

  const f = card("New client", undefined);
  f.appendChild(el("p", "Give it a name. The name is unique and cannot be changed, so use the system that will hold the key.", "lede"));
  const nameField = el("label", "Name", "field");
  const nameInput = el("input"); nameInput.type = "text"; nameInput.placeholder = "billing-service";
  nameField.appendChild(nameInput);
  f.appendChild(nameField);
  const readScope = el("input"); readScope.type = "checkbox"; readScope.checked = true;
  const writeScope = el("input"); writeScope.type = "checkbox"; writeScope.checked = true;
  const scopeList = el("ul", undefined, "plain");
  for (const [box, name, note] of [[readScope, "envelope:read", "list, read, report, document, audit zip"],
    [writeScope, "envelope:write", "create, fill, send, sign, reissue, remind, cancel"]]) {
    const li = el("li");
    const lab = el("label");
    lab.appendChild(box);
    lab.appendChild(document.createTextNode(" " + name));
    li.appendChild(lab);
    li.appendChild(el("span", note, "muted small grow"));
    scopeList.appendChild(li);
  }
  f.appendChild(scopeList);
  f.appendChild(el("p", "A client can hold nothing beyond these two. It is never an admin, so it cannot read the audit log or the settings.", "muted small"));
  const create = button("Create client", "primary", async () => {
    const name = nameInput.value.trim();
    if (!name) { show("A name is required.", "bad"); return; }
    const scopes = [];
    if (readScope.checked) scopes.push("envelope:read");
    if (writeScope.checked) scopes.push("envelope:write");
    create.disabled = true;
    let res;
    try {
      res = await api("/admin/clients", { method: "POST", body: JSON.stringify({ name: name, scopes: scopes }) });
    } catch (err) {
      show(String(err.message || err), "bad"); create.disabled = false; return;
    }
    create.disabled = false;
    if (!res.ok) { show(await problem(res), "bad"); return; }
    const out = await res.json();
    showKeyCreated(out.client || {}, out.key || "", out.note || "");
  });
  f.appendChild(create);
  main.appendChild(f);
}

// The one response that carries a usable secret. The server keeps only a hash,
// so whatever is not on this screen is gone.
function showKeyCreated(client, key, note) {
  view = "/admin/clients";
  const main = shell("Client created", "/admin/clients",
    "Hand these two values to the system that will call the API.");
  const box = el("div", undefined, "keybox");
  const pre = el("pre", key || "(no key returned)");
  box.appendChild(pre);
  box.appendChild(el("p", "This is the only time it is shown. It is stored as a hash, so it cannot be read back.", "note"));
  main.appendChild(box);
  const meta = el("div", undefined, "keymeta");
  meta.appendChild(copyButton(key || ""));
  const idk = el("span", undefined, "k");
  idk.appendChild(document.createTextNode("client id "));
  idk.appendChild(el("b", client.id + "  (subject client:" + client.id + ")"));
  meta.appendChild(idk);
  meta.appendChild(el("span", "name " + (client.name || ""), "k"));
  meta.appendChild(el("span", "scopes " + ((client.scopes || []).join(", ") || "none"), "k"));
  main.appendChild(meta);
  if (note) main.appendChild(el("p", note, "muted small"));
  main.appendChild(el("p", "Use it as the key on POST /api/v1/auth/token; the token it returns is what the API calls carry. The CLI takes it in SIGNSRV_KEY.", "muted small"));
  const back = el("div", undefined, "actions");
  back.appendChild(linkTo("/admin/clients", "Back to the client list", () => showClients()));
  main.appendChild(back);
}

// ----------------------------------------------------------------- settings

async function showSettings() {
  const main = shell("Settings", "/admin/settings", "The running configuration. Values you change here take effect on the next send.");
  let body;
  try {
    body = await getJSON("/admin/settings");
  } catch (err) {
    main.appendChild(el("p", String(err.message || err), "notice bad"));
    return;
  }
  show("");
  const settings = body.settings || body || {};
  const f = card(undefined, undefined);
  const fields = {};
  for (const [key, label, hint, type] of [
    ["tsa_url", "TSA URL", "Where signatures get their timestamps.", "text"],
    ["link_ttl", "Link TTL", "How long a signing link stays valid.", "text"],
    ["mail_from", "Mail from", "The address every invitation is sent from.", "text"],
    ["smtp_host", "SMTP host", "Empty means the outbox stays on disk.", "text"]]) {
    const fl = el("label", label, "field");
    const input = el("input");
    input.type = type;
    input.value = settings[key] === undefined ? "" : String(settings[key]);
    fl.appendChild(input);
    if (hint) fl.appendChild(el("span", hint, "hint"));
    f.appendChild(fl);
    fields[key] = input;
  }
  const save = button("Save", "primary", async () => {
    const patch = {};
    for (const k of Object.keys(fields)) patch[k] = fields[k].value.trim();
    let res;
    try {
      res = await api("/admin/settings", { method: "PATCH", body: JSON.stringify(patch) });
    } catch (err) {
      show(String(err.message || err), "bad"); return;
    }
    if (!res.ok) { show(await problem(res), "bad"); return; }
    const out = await res.json();
    show("Saved. " + ((out.changed || []).join(", ") || "nothing changed."), "ok");
    const after = out.settings || {};
    for (const k of Object.keys(fields)) {
      if (after[k] !== undefined) fields[k].value = String(after[k]);
    }
  });
  f.appendChild(save);
  main.appendChild(f);
  main.appendChild(el("p", "Machine clients live on the Clients page. The audit log is on the dashboard and on GET /admin/events.", "muted small"));
}

// ---------------------------------------------------------------- entry point

if (accessToken) { route(true); } else { pendingPath = currentPath(); showLogin(); }
