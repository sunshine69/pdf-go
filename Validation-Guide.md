# Checking a signed document

*Who this is for: you received a PDF that was signed using this service, and you
want to know it is the real one and nobody changed it afterwards. No account, no
password, no install.*

---

## The short version

1. Download the tool for your computer, from the same website that sent you the
   document:

   - Linux: `https://pdfsign.kaykraft.org/dl/signsrv-linux-amd64`
   - Windows: `https://pdfsign.kaykraft.org/dl/signsrv-windows-amd64.exe`

2. Put the tool and the PDF in the same folder, and open that folder in a
   terminal.

3. On Linux or macOS, say the downloaded file is allowed to run (Windows needs
   nothing here):

   ```sh
   chmod +x signsrv-linux-amd64
   ```

4. Run one command — replace `contract.pdf` with your file's name:

   **Linux / macOS**
   ```sh
   ./signsrv-linux-amd64 checkpdf contract.pdf
   ```

   **Windows** (in PowerShell, from the folder)
   ```powershell
   .\signsrv-windows-amd64.exe checkpdf contract.pdf
   ```

   If Windows names the download something longer, use the name in your folder.

5. Look at the first line of the answer.

---

## Reading the answer

```
{
  "valid": true,
  "trust": "pinned",
  ...
}
```

| You see | It means |
|---|---|
| `"valid": true` and `"trust": "pinned"` | **This is the document that was signed here, and nothing in it has changed.** This is the answer you want. |
| `"valid": false` | The document was changed after it was signed, or is not the file that was signed. Do not treat it as the agreed document. Report it to whoever sent it. |
| `"trust": "none"` | The check ran but did not confirm *who* signed — you used a tool that does not know this service's certificate. See *If the tool does not know the signer* below. |
| The command prints no JSON, and says something about a file not being found | Check you are in the right folder and typed the file's name correctly. |

Everything else in the output is detail: the fingerprints of the file
(`"sha256"`), the names and email addresses of everyone who signed, and the time
each of them signed.

**The exit code is the machine-readable version of the same answer:** 0 means
valid, 1 means not.

---

## What the check actually proves

Two separate things, and it is worth knowing both:

- **Intact** — every signature in the file matches the bytes of the file. Any
  edit, even one character, breaks the signature. This is checked always.
- **From this service** — the certificates that signed the document were issued
  by this service's own certificate authority, not by somebody else's. This is
  checked when `"trust": "pinned"`, which is what the download above gives you.

A document can be internally well-signed by a certificate from anywhere, and look
identical to a reader. `trust: pinned` is what rules that out.

What the check does **not** tell you:

- **Whether the person who signed knew what they were signing.** The signature
  proves a key signed the document, not that the person read it.
- **Whether the document is legally binding.** That depends on your jurisdiction
  and on what was agreed.
- **Anything about a printed copy.** Signatures live in the file. A printout has
  no signature and cannot be checked this way.

---

## If the tool does not know the signer

If you see `"trust": "none"`, the tool ran but cannot say who signed. Use the
download from the website that sent you the document — it carries that site's
certificate. If you cannot get that download, ask the sender for their CA
certificate file and add it to the command:

```sh
./signsrv-linux-amd64 checkpdf -pin ca.crt contract.pdf
```

The tool will then report `"trust": "pinned"` and
`"anchor_source": "-pin ca.crt"`.

You can also check where the tool's certificate came from, rather than taking
the download on trust. Compare this:

```sh
./signsrv-linux-amd64 checkpdf contract.pdf | grep anchor_sha256
```

with what the same website publishes at `/api/v1/ca`. The two `sha256` values
should be equal.

---

## Checking the download itself

If you want to be sure the tool is the file the service published, get the
checksums:

Download the list of checksums next to the tool, then ask the computer to check
the tool against it.

**Linux / macOS**, in the folder holding both files:

```sh
curl -O https://pdfsign.kaykraft.org/dl/signsrv-checksums.txt
sha256sum -c signsrv-checksums.txt
```

It prints `signsrv-linux-amd64: OK` when the file is the one the service
published. Anything else — `FAILED`, or a line saying the file is missing — means
the download is not what was published.

**Windows (PowerShell)**: download
`https://pdfsign.kaykraft.org/dl/signsrv-checksums.txt` into the same folder, then

```powershell
Get-FileHash .\signsrv-windows-amd64.exe -Algorithm SHA256
```

and compare the value it prints with the line in the file for the same name
(letter case does not matter).

---

## Windows says "Windows protected your PC"

Windows warns before running any program it has not seen before, because the tool
is not signed with a Windows code-signing certificate. This is expected and is
not a finding about the document. If you have checked the download against the
checksum above, choose **More info** → **Run anyway**.

---

## Using another program instead

Any PDF reader that shows signature properties (Adobe Acrobat Reader, most
recent browsers' PDF viewers, `pdfsig` on Linux) will show the names, times, and
whether the document changed after signing. They will also say the signer's
certificate is **not trusted**, because this service's certificate authority is
not in your computer's system store — that is expected, and it is what `trust:
pinned` above replaces. For the full manual route, including verifying with
`openssl`, see the technician guide: `Validation-Guide-Technician.md`.

---

## If something is wrong

Tell whoever sent you the document:

- the file's name,
- the whole output of the command, and
- the line `"sha256": "..."`.

That last value identifies the exact bytes you checked, which is what makes the
report useful to someone trying to work out what happened.
