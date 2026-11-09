// Drives the real web/spa/app.js in Node with a minimal DOM, and asks the one
// question the browser asked: does the consent POST carry the image?
//
// The image reaches the server only if the file input's change handler stores
// the data URL somewhere the submit handler can read. Both functions were
// separate top-level functions with a locally-scoped holder, so the upload
// failed silently and the signed PDF had no drawing. Only a DOM run sees that.
import fs from "node:fs";
import vm from "node:vm";
import test from "node:test";
import assert from "node:assert/strict";

// SPA_PATH lets this run against another copy of the app, which is how the
// regression was checked: the same assertions against the previous commit.
const APP_PATH = process.env.SPA_PATH
  ? new URL("file://" + process.env.SPA_PATH)
  : new URL("../../web/spa/app.js", import.meta.url);

class Node {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.children = [];
    this.listeners = {};
    this._text = "";
    this.id = "";
    this.className = "";
    this.value = "";
    this.checked = false;
  }
  get textContent() { return this._text; }
  set textContent(v) { this._text = String(v); }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { this.children.push(c); return c; }
  insertBefore(c) { this.children.unshift(c); return c; }
  removeChild(c) { this.children = this.children.filter((x) => x !== c); }
  remove() {}
  setAttribute() {}
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  querySelector(sel) {
    if (!sel.startsWith("#")) throw new Error("unsupported selector " + sel);
    const want = sel.slice(1);
    const walk = (n) => {
      if (n.id === want) return n;
      for (const c of n.children) { const hit = walk(c); if (hit) return hit; }
      return null;
    };
    return walk(this);
  }
}

// Runs app.js in a sandbox with just enough DOM, renders the consent panel,
// and returns the handle the test drives it through.
async function loadSPA() {
  const app = new Node("div");
  const post = { count: 0, body: null };
  const uncaught = [];
  const sandbox = {
    console,
    // The page arms a 30s refresh timer on render. Nothing in the test waits
    // on it, and keeping it alive would keep the process alive past the
    // assertions, so it is stubbed rather than left to idle out.
    setTimeout: () => 0,
    clearTimeout: () => {},
    AbortController,
    Blob: class {},
    location: { pathname: "/s/" + "a".repeat(52), reload() {} },
    window: { matchMedia: () => ({ matches: false }) },
    document: {
      getElementById: () => app,
      createElement: (t) => new Node(t),
      querySelector: (s) => app.querySelector(s),
    },
    FileReader: class {
      readAsDataURL() {
        this.result = "data:image/png;base64,iVBORw0KGgo=";
        // A browser invokes this from the event loop, so a throw inside it is
        // never seen by the caller. Recorded, not propagated, exactly as a
        // phone would have handled it.
        if (this.onload) {
          try { this.onload({ target: this }); } catch (e) { uncaught.push(e); }
        }
      }
    },
    fetch: async (url, init) => {
      if (url.endsWith("/consent")) {
        post.count++;
        post.body = JSON.parse(init.body);
        return { status: 200, json: async () => ({}), headers: { get: () => null } };
      }
      return {
        status: 200,
        json: async () => ({
          status: "collecting",
          document_sha: "0".repeat(64),
          expires_at: new Date(Date.now() + 86400000).toISOString(),
          title: "Contract",
          parties: [{ order: 1, name: "Ada", status: "sent" }],
          my: { name: "Ada", email: "a@b.c", status: "sent" },
        }),
        headers: { get: () => null },
      };
    },
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  await vm.runInContext(fs.readFileSync(APP_PATH, "utf8"), sandbox);
  // app.js binds these with top-level const/function, which live in the
  // context's own scope rather than on the sandbox object.
  const api = vm.runInContext("({ state, render, readFile })", sandbox);

  // start() landed on the document view; move to the consent panel.
  await new Promise((r) => setTimeout(r, 0));
  api.state.opened = true;
  api.state.view = "consent";
  api.render();

  const find = (pred, n = app) => {
    if (pred(n)) return n;
    for (const c of n.children) { const hit = find(pred, c); if (hit) return hit; }
    return null;
  };
  return {
    sandbox,
    post,
    uncaught,
    fileInput: find((n) => n.tagName === "INPUT" && n.type === "file"),
    textArea: find((n) => n.tagName === "TEXTAREA"),
    checkBox: find((n) => n.tagName === "INPUT" && n.type === "checkbox"),
    signButton: find((n) => n.tagName === "BUTTON" && n.textContent.startsWith("Sign")),
    fire: async (n, type) => {
      const pending = (n.listeners[type] || []).map((fn) => fn({ type }));
      await Promise.all(pending);
    },
  };
}

test("an uploaded signature image is sent with the consent", async () => {
  const t = await loadSPA();
  assert.ok(t.fileInput, "the consent panel offers a signature upload");

  t.fileInput.files = [{ type: "image/png", size: 1024 }];
  await t.fire(t.fileInput, "change");
  await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(t.uncaught, [], "reading the file raised nothing in the page: " + t.uncaught[0]);

  t.textArea.value = "Ada Lovelace";
  await t.fire(t.textArea, "input");
  t.checkBox.checked = true;
  await t.fire(t.checkBox, "change");

  t.signButton.disabled = false;
  await t.fire(t.signButton, "click");

  assert.equal(t.post.count, 1, "the consent was posted");
  assert.ok(t.post.body, "a body was sent");
  assert.equal(t.post.body.signature_text, "Ada Lovelace");
  assert.ok(t.post.body.image, `body carries the image, got keys ${Object.keys(t.post.body)}`);
});

test("a consent without an upload sends no image", async () => {
  const t = await loadSPA();
  t.textArea.value = "Ada Lovelace";
  await t.fire(t.textArea, "input");
  t.checkBox.checked = true;
  await t.fire(t.checkBox, "change");
  t.signButton.disabled = false;
  await t.fire(t.signButton, "click");

  assert.equal(t.post.count, 1);
  assert.equal(t.post.body.image, undefined, "no upload, so no image field");
});
