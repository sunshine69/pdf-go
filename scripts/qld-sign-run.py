#!/usr/bin/env python3
"""qld-sign-run.py — one-shot QLD rental contract: fill the PDF and create the envelope.

    ./scripts/qld-sign-run.py forms/Form-18a-General-tenancy-agreement.pdf --data scripts/qld-agreement.example.yaml

Two inputs: the PDF to fill, and one YAML holding the contract data (field
values, envelope metadata, parties). The PDF may be the positional argument or
the 'pdf:' key in the YAML; the positional wins.

Reads one YAML file holding everything the contract needs (the PDF, the form
field values, the envelope metadata, the parties), fills the form locally with
pdf-go, uploads the finished bytes to the signing service, and stops at
`created` — the service is never asked to send, the admin dispatches from the
dashboard.

Credentials come from the environment, never from the YAML:

    SIGNSRV_URL      service base URL (or the `server:` key in the YAML)
    SIGNSRV_KEY      machine client key  -> exchanged at /api/v1/auth/token
    SIGNSRV_TOKEN    a session token, used as-is, skips the exchange

--dry-run does everything except talk to the service, so it works with no
credentials set.

Exit codes: 0 created; 1 usage or config error; 2 the service refused;
3 created but the post-create check failed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

try:
    import requests
    import yaml
except ImportError as exc:  # pragma: no cover
    sys.exit(f"qld-sign-run: needs a python module: {exc} (pip3 install pyyaml requests)")

# pdf-go is NOT optional: the script fills, verifies and measures the page
# through it. It is a Go binary, so it has to be built or installed - there is
# no pip equivalent and nothing to download at run time. Look for it in this
# order, and name every place that was tried when it is missing.
PDFGO_NAME = "pdf-go"


def resolve_pdfgo(explicit: str | None) -> str:
    """Find the pdf-go binary. An explicit path must exist; otherwise search
    the environment, the PATH, and this checkout's build directory."""
    if explicit:
        path = os.path.expanduser(explicit) if explicit.startswith("~") else explicit
        found = path if os.path.isfile(path) else shutil.which(path)
        if not found:
            die(f"no pdf-go at {path!r} (--pdf-go). Build it:\n"
                f"    go build -o tmp/pdf-go ./cmd/pdf-go")
        return found

    tried = []
    env = os.environ.get("PDFGO", "")
    if env:
        tried.append(f"$PDFGO ({env})")
        path = os.path.expanduser(env) if env.startswith("~") else env
        if os.path.isfile(path) or shutil.which(path):
            return shutil.which(path) or path

    tried.append(f"{PDFGO_NAME} on PATH")
    if shutil.which(PDFGO_NAME):
        return shutil.which(PDFGO_NAME)

    # A checkout of this repo, however the script was reached.
    here = os.path.dirname(os.path.realpath(__file__))
    for root in (os.getcwd(), os.path.dirname(here)):
        build = os.path.join(root, "tmp", PDFGO_NAME)
        tried.append(build)
        if os.path.isfile(build):
            return build

    die("no pdf-go found. The script fills and verifies through it, so it is "
        "required.\n  looked at: " + ", ".join(tried)
        + "\n  build it:  go build -o tmp/pdf-go ./cmd/pdf-go"
        + "\n  or name it: --pdf-go /path/to/pdf-go")



def die(msg: str, code: int = 1) -> None:
    print(f"qld-sign-run: {msg}", file=sys.stderr)
    raise SystemExit(code)


def log(msg: str) -> None:
    print(f"qld-sign-run: {msg}")


# ---------------------------------------------------------------- config ----

def load_config(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError:
        die(f"data file {path} not found")
    except yaml.YAMLError as exc:
        die(f"parse {path}: {exc}")
    if not isinstance(data, dict):
        die(f"{path}: top level must be a mapping")
    return data


def require(data: dict, key: str) -> dict:
    block = data.get(key)
    if not isinstance(block, dict) or not block:
        die(f"data file needs a non-empty '{key}:' mapping")
    return block


def scalar(value, field: str) -> str:
    """A YAML value becomes one string. Dates and numbers arrive typed."""
    if value is None:
        die(f"no value given for {field}")
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, dict)):
        die(f"{field} must be a single value, not a list or mapping")
    if hasattr(value, "strftime"):
        return value.strftime("%d %b %Y")
    return str(value)


def resolve_pdf(data: dict, override: str | None) -> str:
    pdf = override or data.get("pdf")
    if not pdf:
        die("no PDF: pass --pdf or set 'pdf:' in the data file")
    if not os.path.isfile(pdf):
        die(f"PDF not found: {pdf}")
    return pdf


def form_values(data: dict, overrides: dict[str, str]) -> dict[str, str]:
    """field name -> value, from the `form:` block, then --form overrides."""
    block = require(data, "form")
    values: dict[str, str] = {}
    for name, value in block.items():
        if isinstance(value, bool):
            values[str(name)] = value  # checkbox stays a JSON bool
        else:
            values[str(name)] = scalar(value, f"form.{name}")
    for item in overrides.get("form", []):
        if "=" not in item:
            die(f"--form {item!r} wants KEY=VALUE")
        key, value = item.split("=", 1)
        values[key.strip()] = value
    if not values:
        die("the 'form:' block has no fields to fill")
    return values


def parties(data: dict) -> list[dict]:
    rows = data.get("parties")
    if not isinstance(rows, list) or not rows:
        die("data file needs a non-empty 'parties:' list")
    out, seen = [], set()
    for i, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            die(f"party {i} must be a mapping with email/name/order")
        email = scalar(row.get("email"), f"party {i}.email").strip().lower()
        if "@" not in email or email.startswith("@"):
            die(f"party {i}: {email!r} is not an email address")
        if email in seen:
            die(f"party {i}: {email} appears twice; one link per address")
        seen.add(email)
        name = scalar(row.get("name"), f"party {i}.name").strip()
        try:
            order = int(row.get("order", i))
        except (TypeError, ValueError):
            die(f"party {i}: order must be a whole number")
        out.append({"email": email, "name": name, "order": order})
    orders = [p["order"] for p in out]
    if len(set(orders)) != len(orders):
        die(f"two parties share signing order; orders must be unique: {orders}")
    return sorted(out, key=lambda p: p["order"])


def widget(data: dict) -> dict | None:
    block = data.get("widget")
    if not block:
        return None
    if not isinstance(block, dict):
        die("'widget:' must be a mapping (field and/or page/x/y)")
    out = {}
    if block.get("auto"):
        # Placement is decided at run time, from the document itself.
        out["auto"] = True
        if block.get("page") is not None:
            out["page"] = block["page"]
        return out
    if block.get("field"):
        out["field"] = scalar(block["field"], "widget.field")
    for key in ("page", "x", "y"):
        if block.get(key) is not None:
            try:
                out[key] = float(block[key]) if key != "page" else int(block[key])
            except (TypeError, ValueError):
                die(f"widget.{key} must be a number")
    if not out:
        die("'widget:' needs at least a field name or page/x/y")
    return out


BOX_W, BOX_H, STRIDE, MARGIN = 220.0, 80.0, 90.0, 36.0


def stack_height(people: int) -> float:
    """Room a stack of signatures needs above its base y. The service places
    party i at y + STRIDE*i on one page, and clamps rather than refusing, so a
    stack taller than the page piles the extra parties onto the same row."""
    return BOX_H + STRIDE * max(0, people - 1)


def _page_size(pdf_go: str, pdf: str, page, workdir: str):
    """(page number, width, height) for a page number, or the last page."""
    pages = _page_boxes(pdf_go, pdf, workdir)
    num = pages[-1]["index"] if page in (None, "", "last") else int(page)
    info = next((p for p in pages if p["index"] == num), None)
    if info is None:
        die(f"widget page {num} does not exist; the document has {len(pages)} page(s)")
    return num, float(info["width"]), float(info["height"]), len(pages)


def _obstacles(pdf_go: str, pdf: str, num: int, x: float, height: float,
               workdir: str) -> tuple[list, bool]:
    """What stands in the signature's way on one page: form fields and printed
    words, both already in PDF points from the lower-left. Only items in the
    stack's own column count - a form's right-hand margin prints all over and is
    none of our business. The flag says whether poppler was available."""
    fields = _field_rects(pdf_go, pdf, workdir)
    rows, have_text = _text_rows(pdf, num, height, workdir)

    def in_column(x0, x1):
        return not (x1 <= x or x0 >= x + BOX_W)

    blocked = []
    for f in fields:
        if f.get("page") == num and isinstance(f.get("rect"), list) and len(f["rect"]) == 4:
            if in_column(f["rect"][0], f["rect"][2]):
                blocked.append((f["rect"][1], f["rect"][3], f"field {f['name']}"))
    for y0, y1, x0, x1 in rows:
        if in_column(x0, x1):
            blocked.append((y0, y1, "printed text"))
    return blocked, have_text


def _hits(blocked: list, y: float) -> list:
    """Items a box at base y would cover."""
    return [label for y0, y1, label in blocked if not (y1 <= y or y0 >= y + BOX_H)]


def resolve_auto(pdf_go: str, pdf: str, page, people: int, workdir: str) -> dict:
    """auto: true - the last page (where the party blocks usually are), in the
    lowest band of the left column that holds the whole stack.

    The service never searches for free space: it draws where it is told. So the
    script measures instead - page list and field rectangles from pdf-go, printed
    words from pdftotext -bbox. A signature over printed words is a signature
    nobody can read, so the least-crowded band wins, and says so out loud."""
    num, width, height, total = _page_size(pdf_go, pdf, page, workdir)
    need = stack_height(people)

    x = MARGIN
    if x + BOX_W > width - MARGIN:
        x = max(0.0, width - MARGIN - BOX_W)

    blocked, have_text = _obstacles(pdf_go, pdf, num, x, height, workdir)

    best, best_hits = None, None
    y = MARGIN
    while y <= height - MARGIN - BOX_H:
        covered = _hits(blocked, y)
        # The stack must fit above y as well as the first box sitting in the
        # legal band, otherwise the extra parties clamp onto party 1's row.
        fits = y + need <= height - MARGIN
        score = len(covered) + (0 if fits else 1000)
        if best_hits is None or score < best_hits:
            best, best_hits = y, score
            if score == 0:
                break
        y += 5.0

    if best is None:
        best = MARGIN
    covered = _hits(blocked, best)
    if covered or best + need > height - MARGIN:
        log(f"widget:  no band on page {num} holds a {int(need)} pt stack clear of "
            f"print; y={int(best)} is the least crowded "
            f"({len(covered)} item(s) under the first box)")

    log(f"widget:  auto -> page {num} of {total}, x={int(x)} y={int(best)} "
        f"({int(need)} pt stack, {len(blocked)} item(s) in that column"
        f"{'' if have_text else ', printed text not checked'})")
    return {"page": num, "x": round(x, 2), "y": round(best, 2)}


def check_placement(pdf_go: str, pdf: str, wid: dict, people: int, workdir: str) -> None:
    """Report on a placement the drafter named, and on a field anchor.

    A create is refused for a field that does not exist and for a page that does
    not, but never for overlap: the boxes are not drawn until the parties sign,
    so the service has nothing to measure. That is the check the script can do
    and the service cannot, so it runs on every placement, not only auto."""
    if "x" not in wid or "y" not in wid:
        if wid.get("field") and people > 1:
            log(f"widget:  '{wid['field']}' anchors party 1 only; the other "
                f"{people - 1} fall back to the default column on page 1")
        return

    num, width, height, _ = _page_size(pdf_go, pdf, wid["page"], workdir)
    x, y = float(wid["x"]), float(wid["y"])
    blocked, have_text = _obstacles(pdf_go, pdf, num, x, height, workdir)

    worst = 0
    for i in range(people):
        worst = max(worst, len(_hits(blocked, y + STRIDE * i)))
    over_page = y + stack_height(people) > height - MARGIN
    if x > width - MARGIN - BOX_W or y > height - MARGIN - BOX_H:
        log(f"widget:  x={x:g} y={y:g} is outside the legal band on page {num} "
            f"(A4-like {width:g}x{height:g}: x <= {width - MARGIN - BOX_W:g}, "
            f"y <= {height - MARGIN - BOX_H:g}); the service clamps it, it does not refuse")
    if over_page:
        log(f"widget:  {people} parties need {int(stack_height(people))} pt above y={y:g} "
            f"but page {num} ends at {height:g}: the last signatures clamp onto one row")
    if worst:
        log(f"widget:  {worst} item(s) sit under the boxes at x={x:g} y={y:g} "
            f"on page {num}{'' if have_text else ' (printed text not checked)'}")
    elif not over_page:
        log(f"widget:  page {num} x={x:g} y={y:g} - clear of print and of the form fields")


def _page_boxes(pdf_go: str, pdf: str, workdir: str) -> list[dict]:
    out = os.path.join(workdir, "pages.json")
    proc = subprocess.run([pdf_go, "pages", pdf, "-o", out],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        die(f"{pdf_go} pages failed: "
            + ((proc.stderr or proc.stdout).strip().splitlines() or [""])[-1])
    try:
        with open(out, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        die(f"cannot read the page list: {exc}")
    pages = doc.get("pages", doc) if isinstance(doc, dict) else doc
    if not isinstance(pages, list) or not pages:
        die("the page list came back empty")
    return pages


def _field_rects(pdf_go: str, pdf: str, workdir: str) -> list[dict]:
    out = os.path.join(workdir, "geom.json")
    subprocess.run([pdf_go, "extract", pdf, "-o", out], capture_output=True, text=True)
    try:
        with open(out, encoding="utf-8") as fh:
            return json.load(fh)["fields"]
    except (OSError, KeyError, json.JSONDecodeError):
        return []


def _text_rows(pdf: str, page: int, height: float,
               workdir: str) -> tuple[list, bool]:
    """Printed words on the page, grouped into 20 pt bands, in PDF points from
    the bottom (pdftotext counts from the top). Needs poppler; the flag says
    whether it was there, so the caller can say what it could not check."""
    tool = shutil.which("pdftotext")
    if not tool:
        return [], False
    out = os.path.join(workdir, "bbox.xml")
    # pdf may be a relative path and cwd is not here, so hand over the absolute.
    subprocess.run([tool, "-bbox", "-f", str(page), "-l", str(page),
                    os.path.abspath(pdf), out], capture_output=True)
    try:
        xml = open(out, encoding="utf-8", errors="replace").read()
    except OSError:
        return [], False
    # Each word, exact, in PDF points from the lower-left: pdftotext measures
    # from the top, so the word's own bottom edge is height - yMax.
    words = re.findall(r'<word xMin="([\d.]+)" yMin="([\d.]+)" '
                       r'xMax="([\d.]+)" yMax="([\d.]+)">([^<]*)</word>', xml)
    return [(height - float(y1), height - float(y0), float(x0), float(x1))
            for x0, y0, x1, y1, _ in words], True

# ---------------------------------------------------------------- pdf-go ----

def run_pdfgo(binary: str, args: list[str]) -> None:
    proc = subprocess.run([binary] + args, capture_output=True, text=True)
    if proc.returncode != 0:
        detail = (proc.stderr + proc.stdout).strip()
        die(f"{binary} {args[0]} failed (exit {proc.returncode}):\n{detail}", 1)


def fill(binary: str, pdf: str, values: dict, workdir: str) -> tuple[str, list]:
    """fill spec -> (filled PDF, notes). Fails on any field the PDF lacks.

    The notes are the fill's own account of accepted-but-imperfect values: a
    value wider than its box (scaled down to fit), a value longer than maxLen
    (clipped), a newline in a single-line field. None of them is an error, all
    of them change what the page looks like, so they are returned for the
    caller to print. The service counts the same notes in its audit summary;
    matching the local count against that count is a cheap check that the two
    implementations agree about the document.
    """
    spec_path = os.path.join(workdir, "fill-spec.json")
    filled = os.path.join(workdir, "filled.pdf")
    # "source" is what `fill` reads the input document from; the service also
    # accepts it but the template is uploaded separately, so it is dropped below.
    spec = {"source": os.path.abspath(pdf),
            "values": {k: (v if isinstance(v, bool) else str(v)) for k, v in values.items()}}
    with open(spec_path, "w", encoding="utf-8") as fh:
        json.dump(spec, fh, indent=2, ensure_ascii=False)

    proc = subprocess.run([binary, "fill", spec_path, "-o", filled],
                          capture_output=True, text=True)
    notes: list = []
    try:
        notes = list((json.loads(proc.stdout or "{}")).get("notes") or [])
    except ValueError:
        pass  # no JSON on a clean run, and that is not an error
    if proc.returncode != 0:
        # Exit 3 is a partial fill. The answer is JSON, and its unknownFields
        # list is exactly what the drafter needs, so report that instead of the
        # whole document.
        detail = (proc.stderr + proc.stdout).strip()
        try:
            report = json.loads(detail)
        except ValueError:
            report = {}
        # One unknown name aborts the whole fill and the report then lists every
        # field as missing, so the missing list is the cascade, not the cause.
        # The warning names the culprit.
        unknown = sorted({m for w in (report.get("warnings") or [])
                          for m in re.findall(r'unknown field "([^"]+)"', str(w))})
        if unknown:
            die("the PDF has no field(s): " + ", ".join(unknown)
                + "\n  nothing was filled; list the real names with:"
                + f"\n    {binary} extract {pdf} -o schema.json", 1)
        die(f"{binary} fill failed (exit {proc.returncode}):\n{detail}", 1)

    # Verify reads the result back. Exit 3 means the bytes differ from the
    # request, which is a wrong value silently landing in the wrong box.
    proc = subprocess.run([binary, "verify", filled, spec_path], capture_output=True, text=True)
    if proc.returncode not in (0, 3):
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        die("verify failed: " + (detail[-1] if detail else f"exit {proc.returncode}"))
    if proc.returncode == 3:
        print((proc.stdout or "") + (proc.stderr or ""), file=sys.stderr)
        die("the filled PDF does not read back as asked; nothing was uploaded")

    proc = subprocess.run([binary, "extract", filled, "-o",
                           os.path.join(workdir, "filled-schema.json")],
                          capture_output=True, text=True)
    applied = set(values)
    missing: list[str] = []
    if proc.returncode == 0:
        try:
            with open(os.path.join(workdir, "filled-schema.json"), encoding="utf-8") as fh:
                present = {f["name"] for f in json.load(fh)["fields"]}
            missing = sorted(applied - present)
        except (KeyError, json.JSONDecodeError):
            missing = []
    if missing:
        die("the PDF has no field(s): " + ", ".join(missing)
            + "\n  run: pdf-go extract <pdf> -o schema.json to list them")
    return filled, notes


# --------------------------------------------------------------- service ----

def session_token(url: str, key: str, token: str, timeout: float) -> str:
    if token:
        return token
    try:
        resp = requests.post(url.rstrip("/") + "/api/v1/auth/token",
                             json={"key": key}, timeout=timeout)
    except requests.RequestException as exc:
        die(f"cannot reach {url}: {exc}", 2)
    if resp.status_code != 200:
        die(f"{url}/api/v1/auth/token -> HTTP {resp.status_code}: {resp.text.strip()}", 2)
    tok = resp.json().get("access", "")
    if not tok:
        die("the token endpoint answered without an access token", 2)
    return tok


def create(url: str, token: str, filled: str, title: str, parties_json: list,
           spec: dict, expires: str, timeout: float) -> tuple[int, dict]:
    with open(filled, "rb") as fh:
        files = {"template": (os.path.basename(filled), fh, "application/pdf")}
        fields = {
            "parties": json.dumps(parties_json),
            "spec": json.dumps(spec),
        }
        if title:
            fields["title"] = title
        if expires:
            fields["expires_in"] = expires
        try:
            resp = requests.post(url.rstrip("/") + "/api/v1/envelopes",
                                 headers={"Authorization": f"Bearer {token}"},
                                 files=files, data=fields, timeout=timeout)
        except requests.RequestException as exc:
            die(f"upload to {url} failed: {exc}", 2)
    try:
        body = resp.json()
    except ValueError:
        body = {"raw": resp.text}
    return resp.status_code, body


def check_created(url: str, token: str, env_id: str, timeout: float) -> int:
    try:
        resp = requests.get(url.rstrip("/") + f"/api/v1/envelopes/{env_id}",
                            headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
    except requests.RequestException as exc:
        print(f"qld-sign-run: cannot verify envelope: {exc}", file=sys.stderr)
        return 3
    if resp.status_code != 200:
        print(f"qld-sign-run: envelope {env_id} unreadable: HTTP {resp.status_code}",
              file=sys.stderr)
        return 3
    body = resp.json()
    view = body.get("envelope", body)
    status = view.get("status", "?")
    # The envelope view carries its own event list. A dispatch would leave a
    # send-type event behind, so this is how we prove we did not mail anyone.
    kinds = [str(e.get("kind")) for e in (view.get("events") or []) if isinstance(e, dict)]
    if kinds:
        log(f"events:  {', '.join(kinds)}")
        if any(k.startswith(("send", "dispatch", "mail", "notify")) for k in kinds):
            print("qld-sign-run: WARNING: a dispatch event is present; this script "
                  "did not send it, someone else did", file=sys.stderr)
    # The state a create leaves behind is 'ready': the document is filled and
    # waiting for an invitation. 'sent' or later means someone dispatched it,
    # which this script must not cause; 'draft' or 'failed' means the fill never
    # completed. See internal/signflow/state.go for the machine.
    if status == "ready":
        log(f"envelope {env_id} is 'ready' - filled, awaiting dispatch")
        return 0
    if status in ("sent", "collecting", "signed", "completed", "delivered"):
        log(f"envelope {env_id} is '{status}': it has already been dispatched")
        return 0
    print(f"qld-sign-run: envelope {env_id} ended in '{status}', expected 'ready'",
          file=sys.stderr)
    return 3


# ---------------------------------------------------------------- main ------

def parse_args(argv: list[str]) -> argparse.Namespace:
    fs = argparse.ArgumentParser(
        prog="qld-sign-run.py",
        description="fill a QLD rental PDF and create the signing envelope",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""data file layout (all of it required except pdf/server when overridden):
  pdf: forms/Form-18a-General-tenancy-agreement.pdf          # the blank form
  server: https://host               # optional, else SIGNSRV_URL
  envelope: {title:, subject:, message:, expires:, notify:}
  widget: {auto: true}               # last page, band measured from the form
                                     # or {field: sign1} / {page: 2, x: 36, y: 36}
  form:  {z2: "Ann Smith", lock: true}   # FIELD: value  (true/false = checkbox)
  parties: [{email:, name:, order:}, ...]
""",
    )
    fs.add_argument("pdf", nargs="?", metavar="FORM.pdf",
                    help="the blank form to fill; overrides 'pdf:' in the YAML")
    fs.add_argument("--data", "-d", required=True, help="the YAML contract file")
    fs.add_argument("--form", action="append", default=[], metavar="KEY=VALUE",
                    help="override one form field (repeatable)")
    fs.add_argument("--pdf-go", default=os.environ.get("PDFGO"),
                    help="path to the pdf-go binary. Default: $PDFGO, then "
                         "pdf-go on PATH, then ./tmp/pdf-go of this checkout")
    fs.add_argument("--server", help="override the service URL")
    fs.add_argument("--key-env", default="SIGNSRV_KEY",
                    help="env var with the client key (default SIGNSRV_KEY)")
    fs.add_argument("--token-env", default="SIGNSRV_TOKEN",
                    help="env var with a session token (default SIGNSRV_TOKEN)")
    fs.add_argument("--timeout", type=float, default=60.0, help="HTTP timeout seconds")
    fs.add_argument("--keep-dir", action="store_true",
                    help="keep the temp dir with the filled PDF and spec")
    fs.add_argument("--dry-run", action="store_true",
                    help="fill and verify, print the payload, never call the service")
    fs.add_argument("--links-out", metavar="FILE",
                    help="also write the signing links to FILE at mode 0600")
    fs.add_argument("--json", action="store_true", help="print the service answer as JSON")
    ns, unknown = fs.parse_known_args(argv)
    if unknown:
        die("unrecognised argument(s): " + " ".join(unknown))
    return ns


def main(argv: list[str]) -> int:
    ns = parse_args(argv)
    data = load_config(ns.data)

    # Resolve before anything can fail: a missing binary is the operator's
    # problem, not the contract's, and it says so before reading the PDF.
    ns.pdf_go = resolve_pdfgo(ns.pdf_go)
    pdf = resolve_pdf(data, ns.pdf)
    values = form_values(data, {"form": ns.form})
    people = parties(data)
    wid = widget(data)

    env = data.get("envelope") or {}
    if not isinstance(env, dict):
        die("'envelope:' must be a mapping")
    title = scalar(env.get("title", f"Signature requested: {os.path.basename(pdf)}"), "envelope.title")
    expires = scalar(env.get("expires", ""), "envelope.expires")
    # subject, message and notify are stored on the envelope at create and read
    # when someone dispatches it later. This script never dispatches, but the
    # admin gets what the drafter wrote in the YAML.
    mail = {k: scalar(env[k], f"envelope.{k}")
            for k in ("subject", "message", "notify") if env.get(k)}

    url = ns.server or data.get("server") or os.environ.get("SIGNSRV_URL", "")
    url = str(url).strip()

    log(f"pdf-go:  {ns.pdf_go}")
    log(f"data:    {ns.data}")
    log(f"pdf:     {pdf}")
    log(f"fields:  {len(values)} to fill")
    log(f"parties: {len(people)} ({', '.join(p['email'] for p in people)})")

    workdir = tempfile.mkdtemp(prefix="qld-sign-run-")
    try:
        filled, notes = fill(ns.pdf_go, pdf, values, workdir)
        if not os.path.isfile(filled):
            die("fill produced no output")
        log(f"filled:  {filled} ({os.path.getsize(filled)} bytes) verified")
        # Accepted but imperfect values. The form still fills and the run still
        # uploads; these are the lines that explain a squashed or clipped value
        # later, so they are printed rather than buried in the fill report.
        for n in notes:
            if isinstance(n, dict):
                log(f"note:    {n.get('name')}: {n.get('note')}"
                    + (f" [{n.get('value')}]" if n.get("value") else ""))
            else:
                log(f"note:    {n}")

        if wid and wid.get("auto"):
            wid = resolve_auto(ns.pdf_go, pdf, wid.get("page"), len(people), workdir)
        elif wid:
            # A named placement is the drafter's call, so it is not overruled -
            # but the service cannot see an overlap at create and the drafter
            # cannot either, so the script reports what it measures.
            check_placement(ns.pdf_go, pdf, wid, len(people), workdir)

        # The service decodes one JSON document: {"fill":{...},"widget":{...}}.
        # "source" is a local path, meaningless to the service, so the fill
        # shipped over the wire carries the values only.
        spec: dict = {"fill": {"values": {k: (v if isinstance(v, bool) else str(v))
                                          for k, v in values.items()}}}
        if wid:
            spec["widget"] = wid
            log(f"widget:  {json.dumps(wid)}")
        if mail.get("subject"):
            spec["subject"] = mail["subject"]
        if mail.get("message"):
            spec["message"] = mail["message"]
        if mail.get("notify"):
            spec["notify_email"] = mail["notify"]

        if ns.dry_run:
            print(json.dumps({"template": pdf, "filled": filled, "spec": spec,
                              "parties": people, "title": title,
                              "expires_in": expires, "dispatch": "manual"},
                             indent=2, ensure_ascii=False))
            log("dry run: nothing uploaded")
            return 0

        key = os.environ.get(ns.key_env, "")
        token = os.environ.get(ns.token_env, "")
        if not url:
            die(f"no server: set 'server:' in {ns.data} or SIGNSRV_URL")
        if not url.startswith("https://") and not url.startswith("http://"):
            die(f"server URL must start with http(s)://: {url!r}")
        if not key and not token:
            die(f"no credential: set {ns.key_env} (client key) or {ns.token_env} (session token)")
        if url.startswith("http://"):
            log("note: plain HTTP server, the token travels in the clear")

        log(f"server:  {url}")
        tok = session_token(url, key, token, ns.timeout)

        # Retry only where the service told us it refused and stored nothing:
        # 429 (rate limited) and 500 (its own fault, after validation). 502/503/
        # 504 come from a proxy and are ambiguous — the create may have
        # committed upstream while the answer was lost — and the endpoint has no
        # idempotency key, so retrying those can produce a second envelope.
        # Those are reported for the operator to resolve with
        # GET /api/v1/envelopes, not retried here.
        delay, attempt, code, body = 1.0, 0, 0, {}
        while True:
            attempt += 1
            code, body = create(url, tok, filled, title, people, spec, expires, ns.timeout)
            if code in (429, 500) and attempt < 4:
                log(f"HTTP {code}, retrying in {delay:g}s (attempt {attempt}/4)")
                time.sleep(delay)
                delay *= 2
                continue
            if code in (502, 503, 504):
                die(f"create returned HTTP {code}. The envelope may or may not "
                    f"exist - the endpoint has no idempotency key, so this run "
                    f"did not retry. Check: GET {url.rstrip('/')}/api/v1/envelopes", 2)
            break

        if code not in (200, 201):
            err = body.get("error", body)
            die(f"create refused: HTTP {code} {json.dumps(err, ensure_ascii=False)}", 2)

        created = body.get("envelope", {})
        env_id = created.get("id", "")
        fill_sum = body.get("fill", {})
        if ns.json:
            print(json.dumps(body, indent=2, ensure_ascii=False))

        # The create answer carries the signing links, but this script does not
        # dispatch them: an admin pastes them, or the dashboard sends. They are
        # credentials, so they go to a 0600 file rather than the terminal.
        links = body.get("links") or []
        if ns.links_out and links:
            fd = os.open(ns.links_out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"envelope": env_id,
                           "written": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                           "links": links}, fh, indent=2)
            os.chmod(ns.links_out, 0o600)
            log(f"links:   {ns.links_out} (mode 0600) - {len(links)} signing link(s), not mailed")
        elif links:
            log(f"links:   {len(links)} issued, not printed (use --links-out to keep them)")

        log(f"envelope {env_id} created ({created.get('status', '?')})")
        got = len(fill_sum.get("applied") or [])
        if fill_sum.get("applied") is not None:
            log(f"service applied {got} field(s)")
        for miss in fill_sum.get("missing") or []:
            log(f"WARNING: service did not find field {miss}")
        # The audit summary keeps notes as a count only (the text stays in the
        # full fill report). We printed the local notes above, so all that is
        # left to check is that the service's count matches - if it does not,
        # the two implementations disagree about the document.
        notes_srv = fill_sum.get("notes")
        if isinstance(notes_srv, int) and notes_srv != len(notes):
            log(f"WARNING: the service recorded {notes_srv} fill note(s), the local "
                f"fill recorded {len(notes)} - '{ns.pdf_go}' and the service do not "
                f"see the same form; rebuild it")
        # The service fills the uploaded template again with its own Go, from
        # the spec we sent; the local fill is only what we read back for proof.
        # So the two implementations have to agree about the document, and a
        # stale local pdf-go is the usual way they stop agreeing.
        if got and got != len(values):
            log(f"WARNING: asked for {len(values)} field(s), the service applied {got}. "
                f"The local pdf-go ({ns.pdf_go}) and the service do not see the same "
                f"form - rebuild it, and re-check the names with 'extract'")
        log("not dispatched: the admin sends the invitations from the dashboard")

        return check_created(url, tok, env_id, ns.timeout)
    finally:
        if ns.keep_dir:
            log(f"kept:    {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
