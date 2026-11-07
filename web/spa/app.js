// The signing app. No framework, no build step, no third-party JS, no CDN.
// The token is read from location.pathname only, never from storage. Every
// string that comes from the server is written with textContent, so nothing
// the server said is ever parsed as markup.

const app = document.getElementById("app");

const state = {
  token: tokenFromPath(),
  view: "claim",
  opened: false,     // the document view was opened at least once
  claimed: false,
  envelope: null,
};

// ---------------------------------------------------------------------------
// token + api

function tokenFromPath() {
  // The shell route is /s/<token>. The token is 32 random bytes written as
  // lowercase base32 ([a-z2-7], 52 characters) so it survives a URL path with
  // no escaping; nothing else is on the path, so there is nothing to strip
  // beyond the prefix. Anything that is not that shape is not a token, and the
  // app says so instead of sending it to the API.
  const m = /^\/s\/([a-z2-7]{52,64})\/?$/.exec(location.pathname);
  return m ? m[1] : "";
}

const TIMEOUT_MS = 20000;

// api fetches the signing endpoints. credentials same-origin so the session
// cookie rides along. A network error (not an HTTP status) is retried once.
async function api(path, opts = {}, allowRetry = true) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  const init = {
    method: opts.method || "GET",
    credentials: "same-origin",
    signal: controller.signal,
    headers: { "Content-Type": "application/json" },
  };
  if (opts.body) init.body = opts.body;
  let res;
  try {
    res = await fetch("/api/v1/sign/" + state.token + path, init);
  } catch (networkErr) {
    clearTimeout(timer);
    if (allowRetry) return api(path, opts, false);
    throw networkErr;
  }
  clearTimeout(timer);
  return res;
}

// ---------------------------------------------------------------------------
// response handling per the spec

// On 200 parse the JSON. On the codes the app cares about, act; on any other
// 4xx, surface error.message only (a hint is for the operator).
async function handle(res) {
  switch (res.status) {
    case 200:
      return await res.json();
    case 401:
      // The cookie did not come back. If the party already claimed, that is a
      // browser that is not sending cookies.
      if (state.claimed) return fail("Cookies are blocked. Enable cookies for this site and reload.");
      state.view = "claim";
      render();
      return null;
    case 403:
      return serverMessage(res, "this link is issued to a different address");
    case 409: {
      // Stale document_sha means reload. A closed request says so.
      const body = await safeJSON(res);
      state.envelope = await fetchEnvelope();
      render();
      if (state.envelope && closedStatus(state.envelope.status)) return resultView("closed");
      show(body && body.error ? body.error.message : "Reload, the document changed.");
      return null;
    }
    case 410:
      state.view = "result";
      render();
      return resultView("expired");
    case 429: {
      const secs = parseInt(res.headers.get("Retry-After") || "30", 10);
      show("Too many attempts. Try again in " + secs + "s.");
      return null;
    }
    default: {
      const body = await safeJSON(res);
      if (body && body.error) show(body.error.message);
      return null;
    }
  }
}

async function serverMessage(res, fallback) {
  const body = await safeJSON(res);
  show(body && body.error ? body.error.message : fallback);
  return null;
}

async function safeJSON(res) {
  try {
    return await res.json();
  } catch (e) {
    return null;
  }
}

async function fetchEnvelope() {
  const res = await api("/envelope");
  if (res.status === 200) {
    state.envelope = await res.json();
    return state.envelope;
  }
  await handle(res);
  return null;
}

// ---------------------------------------------------------------------------
// the four views

function render() {
  clear();
  switch (state.view) {
    case "claim": renderClaim(); break;
    case "document": renderDocument(); break;
    case "consent": renderConsent(); break;
    case "result": renderResult(); break;
  }
}

function clear() {
  while (app.firstChild) app.removeChild(app.firstChild);
}

// textContent only, so a server string is never a tag.
function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (cls) node.className = cls;
  return node;
}

function clearMessage() {
  const p = app.querySelector("#statusline");
  if (p) p.remove();
}

function show(message) {
  clearMessage();
  const p = el("p", message, "notice");
  p.id = "statusline";
  app.insertBefore(p, app.firstChild);
}

function fail(message) {
  clear();
  app.appendChild(el("h1", "Cannot continue"));
  app.appendChild(el("p", message));
  const again = el("button", "Reload", "primary");
  again.addEventListener("click", () => location.reload());
  app.appendChild(again);
}

// 1. claim ------------------------------------------------------------------

function renderClaim() {
  app.appendChild(el("h1", "Signature requested"));
  app.appendChild(el("p", "You are signing as the person this link was sent to.", "muted"));

  const form = el("form", undefined, "field");
  form.appendChild(el("label", "Your email address"));
  const input = el("input");
  input.type = "email";
  input.setAttribute("autofocus", "");
  input.setAttribute("autocomplete", "email");
  form.appendChild(input);
  const button = el("button", "Continue", "primary");
  form.appendChild(button);
  app.appendChild(form);
  app.appendChild(el("p", "The status bar above shows any problem with this link.", "muted"));

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const res = await api("/claim", {
      method: "POST",
      body: JSON.stringify({ email: input.value.trim() }),
    });
    const body = await handle(res);
    if (!body) return;
    state.claimed = true;
    state.view = "document";
    state.envelope = await fetchEnvelope();
    if (state.envelope) render();
  });
  button.addEventListener("click", () => form.requestSubmit());
}

// 2. document ---------------------------------------------------------------

function renderDocument() {
  const env = state.envelope;
  if (!env) { fetchEnvelope().then(() => state.envelope && render()); return; }

  clearMessage();
  app.appendChild(el("h1", env.title || "Document"));
  app.appendChild(countdown(env.expires_at));

  const frame = el("iframe");
  frame.title = "Document to review";
  frame.src = "/api/v1/sign/" + state.token + "/document";
  app.appendChild(frame);

  const dl = el("a", "Download to review");
  dl.href = "/api/v1/sign/" + state.token + "/document";
  dl.setAttribute("download", "");
  app.appendChild(dl);
  app.appendChild(el("p", "The document in the frame is the copy your consent will be about.", "muted"));
  // Some phone browsers show an empty frame. The download is the same bytes,
  // so the review can happen outside the page and the signing still happens
  // here. The page is deliberately explicit about it rather than leaving the
  // signer with a blank box and no instruction.
  app.appendChild(el("div",
    "If the frame above is blank on your device: press Download to review, open the PDF that is saved, then return to this page and continue. Downloading does not sign anything.",
    "notice"));

  renderParties(env.parties);

  // The iframe is not the consent. The panel below is.
  state.opened = true;
  app.appendChild(el("button", "I have reviewed it: continue", "primary"))
    .addEventListener("click", () => { state.view = "consent"; render(); });
}

function renderParties(parties) {
  if (!parties || !parties.length) return;
  app.appendChild(el("h1", "Everyone on this request"));
  const list = el("ul", undefined, "parties");
  for (const p of parties) {
    const li = el("li");
    li.textContent = "Party " + p.order + ": " + p.name + " — " + p.status;
    list.appendChild(li);
  }
  app.appendChild(list);
}

function countdown(expiresAt) {
  const p = el("p", undefined, "muted");
  p.id = "statusline";
  if (!expiresAt) { p.textContent = "No expiry on this link."; return p; }
  const deadline = Date.parse(expiresAt);
  const tick = () => {
    const left = deadline - Date.now();
    if (left <= 0) { p.textContent = "This link has expired."; return; }
    const mins = Math.floor(left / 60000);
    const hrs = Math.floor(mins / 60);
    p.textContent = hrs > 0
      ? "Expires in " + hrs + "h " + (mins % 60) + "m"
      : "Expires in " + mins + "m";
    setTimeout(tick, 30000);
  };
  tick();
  return p;
}

// 3. consent ----------------------------------------------------------------

function renderConsent() {
  const env = state.envelope;
  if (!env) { fetchEnvelope().then(() => state.envelope && render()); return; }

  clearMessage();
  app.appendChild(el("h1", "Your consent"));

  const mine = env.my || {};
  app.appendChild(el("p", "You are signing as " + (mine.name || "the invited party")));
  app.appendChild(el("p", "You are reviewing document " + shortSHA(env.document_sha) + ".", "muted"));

  // A read-only display of the signature text, then the textarea that feeds it.
  const nameField = el("label", "Your typed signature (your name)")
  const textarea = el("textarea");
  textarea.rows = 2;
  textarea.maxLength = 120;
  nameField.appendChild(textarea);
  app.appendChild(nameField);
  const counter = el("div", "0 / 120", "counter");
  app.appendChild(counter);

  const fileField = el("label", "Drawn signature (optional, PNG or JPEG, up to 512 KB)")
  const file = el("input");
  file.type = "file";
  file.accept = "image/png,image/jpeg";
  fileField.appendChild(file);
  app.appendChild(fileField);
  // readFile fills this in; the consent body sends it.
  const imageData = { sha: "" };
  file.addEventListener("change", () => {
    const f = file.files && file.files[0];
    if (!f) { imageData.sha = ""; return; }
    if (!/^image\/(png|jpeg)$/.test(f.type)) { show("That is not a PNG or a JPEG."); file.value = ""; return; }
    if (f.size > 512 * 1024) { show("The image is over 512 KB."); file.value = ""; return; }
    readFile(f);
  });

  const check = el("div", undefined, "checkline");
  const box = el("input");
  box.type = "checkbox";
  box.checked = false;
  const label = el("label", "I have read the document and agree to sign it electronically. My typed name above is my signature.");
  check.appendChild(box);
  check.appendChild(label);
  app.appendChild(check);

  const row = el("div", undefined, "row");
  const agree = el("button", "Sign", "primary");
  agree.disabled = true;
  const decline = el("button", "Decline");
  row.appendChild(agree);
  row.appendChild(decline);
  app.appendChild(row);

  renderParties(env.parties);

  const sync = () => {
    counter.textContent = textarea.value.length + " / 120";
    agree.disabled = !(textarea.value.trim().length > 0 && box.checked && state.opened);
  };
  textarea.addEventListener("input", sync);
  box.addEventListener("change", sync);

  agree.addEventListener("click", async () => {
    const body = {
      signature_text: textarea.value.trim(),
      consent: true,
      document_sha: env.document_sha,
    };
    if (imageData.sha) body.image = imageData.sha;
    const res = await api("/consent", { method: "POST", body: JSON.stringify(body) });
    const out = await handle(res);
    if (!out) return;
    state.envelope = await fetchEnvelope();
    renderResult(out.all_consented ? "consented" : "consented");
  });

  decline.addEventListener("click", async () => {
    const reason = window.prompt("Why are you declining? (optional)") || "";
    const res = await api("/decline", { method: "POST", body: JSON.stringify({ reason }) });
    const out = await handle(res);
    if (!out) return;
    renderResult("closed");
  });
}

// The file is read into a data: URL, which is the only place the image is held
// in this app: the bytes go to the server and the server answers with a sha.
function readFile(f) {
  const reader = new FileReader();
  reader.onload = () => {
    // The data URL is the body the server accepts; it lives only for the
    // duration of this panel and is never written to storage.
    imageData.sha = String(reader.result);
    show("Image attached.");
  };
  reader.readAsDataURL(f);
}

function shortSHA(sha) {
  return sha ? String(sha).slice(0, 8) : "";
}

// 4. result -----------------------------------------------------------------

function renderResult(which) {
  state.view = "result";
  clear();
  const copy = {
    consented: "Your agreement is recorded. The document is signed and sent to everyone once all parties have agreed.",
    expired: "This link has expired. Ask for a new one.",
    closed: "This request is closed. Nothing is signed.",
    delivered: "The signed document is available.",
  };
  app.appendChild(el("h1", "Thank you"));
  app.appendChild(el("p", copy[which] || copy.closed));
  const env = state.envelope;
  if (env && env.my && env.my.consent_at) {
    app.appendChild(el("p", "Recorded at " + env.my.consent_at + ".", "muted"));
  }
}

// ---------------------------------------------------------------------------

function closedStatus(status) {
  return ["cancelled", "expired", "failed", "completed", "delivered"].includes(status);
}

// The entry point. The envelope view answers 401 before the claim and the full
// view after it, so the same call picks the first view.
(async function start() {
  if (!state.token) { fail("This page must be opened from your signing link."); return; }
  const res = await api("/envelope");
  if (res.status !== 200) { await handle(res); return; }
  state.envelope = await res.json();
  // The envelope view answers with the title and the deadline only until the
  // address is claimed: the party slot ("my") is the proof that this browser
  // proved its address, so it is what the first view is chosen from. A claimed
  // party still reviewing sees the document; a party that has consented sees
  // the record of its own consent.
  state.claimed = Boolean(state.envelope.my);
  if (!state.claimed) { state.view = "claim"; render(); return; }
  const reviewing = state.envelope.status === "sent" || state.envelope.status === "collecting";
  state.view = reviewing && state.envelope.my.status === "invited" ? "document" : "consent";
  render();
})();
