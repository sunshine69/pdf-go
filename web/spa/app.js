// The signing app. No framework, no build step, no third-party JS, no CDN.
// The token is read from location.pathname only, never from storage. Every
// string that comes from the server is written with textContent, so nothing
// the server said is ever parsed as markup.

const app = document.getElementById("app");

const state = {
  token: tokenFromPath(),
  view: "claim",
  opened: false,     // the document view was opened at least once
  resultKey: "",     // which result copy to show when the view is re-rendered
  claimed: false,
  envelope: null,
  // The server's note about the typed signature not fitting the stamp. It
  // arrives with the consent answer and is shown on the result page; kept in
  // state so a re-render does not lose the only copy of it.
  stampNote: "",
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
      if (state.envelope && closedStatus(state.envelope.status)) return renderResult("closed");
      show(body && body.error ? body.error.message : "Reload, the document changed.");
      return null;
    }
    case 410:
      state.view = "result";
      render();
      return renderResult("expired");
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

// stampFits reports whether a typed signature can be printed in the stamp on
// the page. The rule mirrors signpdf.StampText on the server: the appearance
// font is a simple WinAnsi font, so the server encodes the line to cp1252 bytes
// and drops any line containing a character cp1252 has no code point for --
// Vietnamese, Thai, Cyrillic, Greek, CJK. It is the font dictionary that is the
// limit, not the glyphs: Patrick Hand itself covers Vietnamese.
//
// The set below is the server's: printable ASCII, the Latin-1 supplement
// 0xA0-0xFF, and the 27 characters cp1252 maps into 0x80-0x9F. A character
// outside it is dropped, so a party who types one is warned that the stamp will
// not carry it -- though their words are still kept in full on the record.
const STAMP_CP1252_EXTRA = new Set([
  0x20ac, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030,
  0x0160, 0x2039, 0x0152, 0x017d, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022,
  0x2013, 0x2014, 0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0x017e, 0x0178,
]);

function stampFits(s) {
  for (const c of s) {
    const cp = c.codePointAt(0);
    if (cp >= 0x20 && cp <= 0x7e) continue;
    if (cp >= 0xa0 && cp <= 0xff) continue;
    if (STAMP_CP1252_EXTRA.has(cp)) continue;
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// the four views

function render() {
  clear();
  switch (state.view) {
    case "claim": renderClaim(); break;
    case "document": renderDocument(); break;
    case "consent": renderConsent(); break;
    case "result": renderResult(state.resultKey); break;
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

  // Chrome on Android does not render a PDF inside a frame: the box comes up
  // blank with no explanation, and a refresh after it does not help. A device
  // with a coarse pointer is asked to open the document in its own viewer or
  // download it; a desktop gets the frame inline.
  const phone = window.matchMedia && window.matchMedia("(pointer: coarse)").matches;
  const docURL = "/api/v1/sign/" + state.token + "/document";
  if (!phone) {
    const frame = el("iframe");
    frame.title = "Document to review";
    frame.src = docURL;
    app.appendChild(frame);
  }

  const links = el("div", undefined, "row");
  const open = el("a", "Open the document", "primary");
  open.href = docURL;
  open.target = "_blank";
  open.rel = "noopener";
  const dl = el("a", "Download to review");
  dl.href = docURL;
  dl.setAttribute("download", "");
  links.appendChild(open);
  links.appendChild(dl);
  app.appendChild(links);
  app.appendChild(el("div", phone
    ? "Your device does not show the document inside this page. Open or download the PDF, read it, then come back to this page and continue. Neither button signs anything."
    : "The document in the frame is the copy your consent will be about.", "notice"));

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

  const mine = env.my || {};
  // A party that already answered, or a request that is closed, has no form to
  // fill: there is no re-consent path. Showing the panel anyway produces a
  // form whose Sign can never enable, which reads as a broken page. The record
  // of the decision is shown instead.
  if (closedStatus(env.status) || mine.status === "consented" || mine.status === "declined" ||
      mine.status === "expired") {
    renderResult(mine.status === "declined" ? "declined" :
      (closedStatus(env.status) ? "closed" : "consented"));
    return;
  }

  clearMessage();
  app.appendChild(el("h1", "Your consent"));

  app.appendChild(el("p", "You are signing as " + (mine.name || "the invited party")));
  app.appendChild(el("p", "You are reviewing document " + shortSHA(env.document_sha) + ".", "muted"));

  // The review view is always reachable again: a phone that opened the document
  // and reloaded must not be stranded here with no way back to the copy it is
  // consenting about.
  const back = el("a", "Back to the document");
  back.href = "#";
  back.addEventListener("click", (e) => {
    e.preventDefault();
    state.view = "document";
    render();
  });
  app.appendChild(back);

  // A read-only display of the signature text, then the textarea that feeds it.
  const nameField = el("label", "Your typed signature (your name)")
  const textarea = el("textarea");
  textarea.rows = 2;
  textarea.maxLength = 120;
  nameField.appendChild(textarea);
  app.appendChild(nameField);
  const counter = el("div", "0 / 120", "counter");
  app.appendChild(counter);

  // The stamp prints what WinAnsiEncoding can address, and a line using
  // anything else is dropped rather than printed wrong (signpdf.StampText is
  // the rule the server applies). This warning is shown while the party can
  // still retype; the server repeats the same fact after the consent is
  // recorded.
  const stampHint = el("div", "", "stamp-hint");
  app.appendChild(stampHint);

  const fileField = el("label", "Drawn signature (optional, PNG or JPEG, up to 512 KB)")
  const file = el("input");
  file.type = "file";
  file.accept = "image/png,image/jpeg";
  fileField.appendChild(file);
  app.appendChild(fileField);
  // readFile fills this in; the consent body sends it.
  const imageData = { dataURL: "" };
  file.addEventListener("change", () => {
    const f = file.files && file.files[0];
    if (!f) { imageData.dataURL = ""; return; }
    if (!/^image\/(png|jpeg)$/.test(f.type)) { show("That is not a PNG or a JPEG."); file.value = ""; return; }
    if (f.size > 512 * 1024) { show("The image is over 512 KB."); file.value = ""; return; }
    readFile(f, imageData);
  });

  // The box and its words are joined by for/id, not by nesting a box inside a
  // label: on a phone a nested label can swallow the tap, so the box looks
  // ticked while the consent flag never fires.
  const check = el("div", undefined, "checkline");
  const box = el("input");
  box.type = "checkbox";
  box.id = "consent-box";
  box.checked = false;
  box.setAttribute("aria-describedby", "consent-hint");
  const label = el("label", "I have read the document and agree to sign it electronically. My typed name above is my signature.");
  label.htmlFor = "consent-box";
  check.appendChild(box);
  check.appendChild(label);
  app.appendChild(check);
  const hint = el("div", "Sign stays disabled until the name is typed and this box is ticked.", "muted");
  hint.id = "consent-hint";
  app.appendChild(hint);

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
    // Mirror of signpdf.StampText: the characters WinAnsiEncoding addresses.
    // Iterating by code point rather than code unit matters now that
    // non-ASCII can pass -- a surrogate pair is one character, and an
    // astral character is outside WinAnsiEncoding, so it is dropped.
    const t = textarea.value.trim();
    stampHint.textContent = t && !stampFits(t)
      ? "Note: this uses characters the signature stamp cannot print, so it will be recorded but not shown in the box on the page."
      : "";
    agree.disabled = !(textarea.value.trim().length > 0 && box.checked && state.opened);
  };
  textarea.addEventListener("input", sync);
  // Some mobile browsers fire input and not change on a box, so both are
  // listened to and the state is read from the box rather than from the event.
  box.addEventListener("change", sync);
  box.addEventListener("input", sync);
  sync();

  agree.addEventListener("click", async () => {
    const body = {
      signature_text: textarea.value.trim(),
      consent: true,
      document_sha: env.document_sha,
    };
    if (imageData.dataURL) body.image = imageData.dataURL;
    const res = await api("/consent", { method: "POST", body: JSON.stringify(body) });
    const out = await handle(res);
    if (!out) return;
    // The server decides what the stamp can print, so it is the one that says
    // whether the typed line made it. An empty note is the normal case.
    state.stampNote = typeof out.stamp_note === "string" ? out.stamp_note : "";
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
//
// The target is a parameter, not a captured variable. `imageData` belongs to
// the consent panel that created the file input, so a top-level function that
// named it directly would refer to nothing at all: the assignment throws
// ReferenceError inside FileReader.onload, an async callback nobody catches, and
// the upload then vanishes with no message and no trace in the request the
// browser sends. A test cannot see that either, so the dependency is spelled
// out instead.
function readFile(f, imageData) {
  const reader = new FileReader();
  reader.onload = () => {
    // The data URL is the body the server accepts; it lives only for the
    // duration of this panel and is never written to storage.
    imageData.dataURL = String(reader.result);
    show("Image attached.");
  };
  reader.onerror = () => show("That file could not be read.");
  reader.readAsDataURL(f);
}

function shortSHA(sha) {
  return sha ? String(sha).slice(0, 8) : "";
}

// 4. result -----------------------------------------------------------------

function renderResult(which) {
  state.view = "result";
  if (which) state.resultKey = which;
  which = which || state.resultKey;
  clear();
  const copy = {
    consented: "Your agreement is recorded. The document is signed and sent to everyone once all parties have agreed.",
    expired: "This link has expired. Ask for a new one.",
    closed: "This request is closed. Nothing is signed.",
    delivered: "The signed document is available.",
    declined: "You declined this document. Nothing is signed. Ask the sender for a new request if you changed your mind.",
  };
  app.appendChild(el("h1", "Thank you"));
  app.appendChild(el("p", copy[which] || copy.closed));
  const env = state.envelope;
  if (env && env.my && env.my.consent_at) {
    app.appendChild(el("p", "Recorded at " + env.my.consent_at + ".", "muted"));
  }
  // The server's own account of the stamp, shown here because this is the page
  // the party reads after pressing agree. A reload clears it: the note belongs
  // to the consent that just happened, and the receipt is the durable record.
  if (state.stampNote) {
    app.appendChild(el("p", state.stampNote, "muted"));
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
  const mine = state.envelope.my;
  const answered = mine.status === "consented" || mine.status === "declined" || mine.status === "expired";
  // A reload must land where the party last was, not past it. A party that has
  // not answered gets the review view again, so refreshing can never jump into
  // the consent panel and leave no way back. A party that answered, or a
  // request that is closed, gets the record of that decision: there is no
  // second consent to give.
  if (closedStatus(state.envelope.status) || answered) {
    renderResult(answered ? mine.status : "closed");
    return;
  }
  const reviewing = state.envelope.status === "sent" || state.envelope.status === "collecting";
  state.view = reviewing ? "document" : "consent";
  render();
})();
