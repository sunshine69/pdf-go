#!/usr/bin/env python3
"""verify_pdf.py - check every PDF signature using only openssl.

A signature in a signed PDF covers the bytes listed in its /ByteRange, which
skip the signature's own blob. Rebuilding that byte range and comparing its
digest with the one inside the PKCS#7 is the integrity check: it proves the
document has not changed since the signature was made. The chain check needs
the CA as a trust anchor and is run at the signing time, because a party
certificate is valid for 15 minutes and the signature is proof of when it was
made, not of how long the certificate lives.

Usage:
    python3 scripts/verify_pdf.py doc.pdf [ca.crt]

Exit 0 when every signature's digest matches. Non-zero otherwise.
"""
import re, sys, os, subprocess, tempfile, calendar

if len(sys.argv) < 2:
    print(__doc__)
    sys.exit(2)

pdf = open(sys.argv[1], "rb").read()
ca = sys.argv[2] if len(sys.argv) > 2 else None

work = tempfile.mkdtemp(prefix="verifypdf")
ranges = [list(map(int, m)) for m in
          re.findall(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", pdf)]

if not ranges:
    print("%s: no /ByteRange found - this file is not signed" % sys.argv[1])
    sys.exit(2)

ok = True
# Three-valued: None means no CA was supplied, so trust was never assessed.
chain_ok = True if ca else None
for i, (a, b, c, d) in enumerate(ranges, 1):
    content = pdf[a:a + b] + pdf[c:c + d]
    # The gap between the two ranges holds this signature's blob, zero padded.
    hexs = pdf[a + b:c].strip().strip(b"<>").decode().rstrip("0")
    if len(hexs) % 2:
        hexs += "0"
    blob = bytes.fromhex(hexs)
    cf = os.path.join(work, "s%d.content" % i)
    pf = os.path.join(work, "s%d.p7b" % i)
    lf = os.path.join(work, "s%d.leaf" % i)
    open(cf, "wb").write(content)
    open(pf, "wb").write(blob)

    # The leaf is the first certificate in the PKCS#7; the CA follows it.
    certs = subprocess.run(["openssl", "pkcs7", "-inform", "DER", "-in", pf,
                            "-print_certs"], capture_output=True, text=True).stdout
    blocks = [b for b in re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                                    certs, re.S)]
    if blocks:
        open(lf, "w").write(blocks[0] + "\n")

    # Digest check: the only step that needs nothing outside the PDF.
    r = subprocess.run(["openssl", "smime", "-verify", "-inform", "DER",
                        "-in", pf, "-content", cf, "-noverify",
                        "-out", cf + ".out"], capture_output=True, text=True)
    digest = "OK" if r.returncode == 0 else "FAILED"
    if r.returncode != 0:
        ok = False

    # Signing time: the UTC time recorded inside the signature.
    ap = subprocess.run(["openssl", "asn1parse", "-inform", "DER", "-in", pf],
                        capture_output=True, text=True).stdout
    lines = ap.splitlines()
    idx = [j for j, l in enumerate(lines) if "signingTime" in l]
    st = None
    for l in lines[idx[0]:idx[0] + 6] if idx else []:
        m = re.search(r"UTCTIME\s+:(\d+Z)", l)
        if m:
            st = m.group(1)
            break
    attime = None
    if st:
        # The UTCTIME year is two digits; UTCTIME is defined for 2000-2049.
        y = 2000 + int(st[0:2])
        attime = calendar.timegm((y, *[int(st[k:k + 2]) for k in
                                      (2, 4, 6, 8, 10)]))

    subj = subprocess.run(["openssl", "x509", "-in", lf, "-noout", "-subject",
                           "-nameopt", "compat"], capture_output=True,
                          text=True).stdout.strip() if os.path.exists(lf) else ""
    print("signature %d" % i)
    print("   signer:   %s" % subj.split("=", 1)[-1] if subj else "   signer:   -")
    print("   signed:   %d bytes, at %s" % (len(content), st or "unknown"))
    print("   digest:   %s" % digest)

    if not ca:
        continue
    # Chain check at the signing time, since the leaf expires 15 minutes after
    # it is issued. Verifying "today" reports an expired certificate for a
    # signature that was valid when it was made.
    t = str(attime) if attime else None
    args = ["openssl", "verify", "-CAfile", ca]
    if attime:
        args += ["-attime", t]
    args.append(lf)
    v = subprocess.run(args, capture_output=True, text=True)
    line = (v.stdout + v.stderr).strip().splitlines()
    tail = line[-1] if line else "no result"
    if "OK" in tail:
        chain = "OK"
    else:
        # Strip the scratch path openssl prints, so the reason is what a
        # reader sees. The usual reasons are "certificate has expired" and
        # "unable to get issuer certificate" (the CA you gave did not sign it).
        m = re.search(r": (verification failed|certificate has expired|"
                      r"certificate revoked|.*self[- ]signed chain.*|"
                      r"unable to [a-z ]+)", tail)
        chain = m.group(1) if m else tail
    print("   chain:    %s%s" % (chain, "" if attime else " (today)"))

    if chain != "OK":
        chain_ok = False

print()
print("OVERALL:", "all digests verify" if ok
      else "a signature does not match the document (the file was changed after signing)")
if ca:
    print("trust:", "every chain leads to the CA you supplied" if chain_ok
          else "a chain does not lead to the CA you supplied (check the fingerprint, \u00a75)")
else:
    if ok:
        print("Trust was not assessed: no CA was supplied.")
        print("Give the CA as the second argument to check the chains.")
sys.exit(0 if ok and (chain_ok or chain_ok is None) else 1)
