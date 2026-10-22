#!/usr/bin/env python3
"""verifypass.py - Easy Wallet Card: check a .pkpass: manifest SHA-1s, signature, trust chain, signer/pass.json ID match,
sharingProhibited, no web service.

Default prints field keys/labels with value LENGTHS only. --show-except K1,K2 prints every other value.
--root ROOT --wwdr WWDR (REQUIRED unless --no-chain): full chain verification (signer -> pinned WWDR G4 -> pinned Apple Root CA).
  Trust comes ONLY from these two files: system CA dirs/files/stores are disabled (-no-CApath -no-CAfile
  -no-CAstore) and SSL_CERT_DIR/SSL_CERT_FILE are stripped from openssl's environment. Both files must
  match Apple's pinned SHA-256 unless --test-unpinned-chain (throwaway test chains only).
--no-chain: explicitly skip the chain (signature math only); prints WARN and RESULT OK-UNTRUSTED, never RESULT OK.
--cert PASS_CER: the embedded signer cert must be byte-identical (DER SHA-256) to this cert.
--card CARD_JSON: pass.json sharingProhibited must equal the card's request (default true, as in makepass).
Exit codes: 0 = RESULT OK, 1 = RESULT FAILED, 2 = usage error, 3 = RESULT OK-UNTRUSTED (--no-chain:
every other check passed but the trust chain was not verified).
"""
import argparse, atexit, hashlib, json, os, shutil, signal, subprocess, sys, tempfile, zipfile

WWDR_G4_SHA256 = "ea4757885538dd8cb59ff4556f676087d83c85e70902c122e42c0808b5bce14c"
APPLE_ROOT_SHA256 = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"
WWDR_G4_DN = "C=US,O=Apple Inc.,OU=G4,CN=Apple Worldwide Developer Relations Certification Authority"  # RFC2253 order
NO_DEFAULT_TRUST = ["-no-CApath", "-no-CAfile", "-no-CAstore"]
# openssl must not pick up trust anchors from the environment
ENV = {k: v for k, v in os.environ.items() if k not in ("SSL_CERT_DIR", "SSL_CERT_FILE")}

ok_all = True
_WORKDIRS = []


def _cleanup():
    while _WORKDIRS:
        shutil.rmtree(_WORKDIRS.pop(), ignore_errors=True)


def _on_signal(signum, _frame):
    _cleanup()
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)


def check(cond, msg):
    global ok_all
    print(("PASS " if cond else "FAIL ") + msg)
    ok_all &= bool(cond)


def run(*args, binary=False):
    r = subprocess.run(list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
    out = r.stdout if binary else r.stdout.decode("utf-8", "replace")
    return r.returncode, out, r.stderr.decode("utf-8", "replace")


def der_bytes(src):
    """DER bytes of a .cer/.pem certificate (first cert)."""
    form = "PEM" if b"-----BEGIN" in open(src, "rb").read(64) else "DER"
    rc, out, err = run("openssl", "x509", "-inform", form, "-in", src, "-outform", "DER", binary=True)
    if rc:
        sys.exit(f"cannot read cert {src}: {err.strip()}")
    return out


def write_pem(src, dst):
    form = "PEM" if b"-----BEGIN" in open(src, "rb").read(64) else "DER"
    rc, _, err = run("openssl", "x509", "-inform", form, "-in", src, "-out", dst)
    if rc:
        sys.exit(f"cannot read cert {src}: {err.strip()}")


def dn(pem, which):
    rc, out, _ = run("openssl", "x509", "-in", pem, "-noout", f"-{which}", "-nameopt", "RFC2253")
    return out.strip().split("=", 1)[1] if rc == 0 and "=" in out else None


def main():
    ap = argparse.ArgumentParser(allow_abbrev=False, description="Easy Wallet Card: verify a .pkpass. "
                                 "Exit 0 OK, 1 FAILED, 2 usage error, 3 OK-UNTRUSTED (--no-chain).")
    ap.add_argument("pkpass")
    ap.add_argument("--root", help="Apple Root CA cert (.cer/.pem) for chain verification")
    ap.add_argument("--wwdr", help="Apple WWDR G4 intermediate (.cer/.pem) for chain verification")
    ap.add_argument("--cert", help="expected signer cert (pass.cer); embedded signer must be byte-identical")
    ap.add_argument("--card", help="card JSON; sharingProhibited in pass.json must match its request")
    ap.add_argument("--no-chain", action="store_true",
                    help="explicitly skip trust-chain verification (signature math only); result is marked UNTRUSTED")
    ap.add_argument("--test-unpinned-chain", action="store_true",
                    help="allow --root/--wwdr that are NOT Apple's pinned certs (throwaway test chains only)")
    ap.add_argument("--show-except", default=None,
                    help="comma-separated field keys to redact; all other values are printed")
    a = ap.parse_args()
    if bool(a.root) != bool(a.wwdr):
        ap.error("--root and --wwdr go together")
    if a.no_chain and a.root:
        ap.error("--no-chain cannot be combined with --root/--wwdr")
    if not a.no_chain and not a.root:
        ap.error("--root and --wwdr are required (or pass --no-chain to explicitly skip the trust chain)")
    if a.no_chain and a.test_unpinned_chain:
        ap.error("--test-unpinned-chain needs --root/--wwdr")
    os.umask(0o077)
    atexit.register(_cleanup)
    for sg in SIGNALS:
        signal.signal(sg, _on_signal)
    signal.pthread_sigmask(signal.SIG_BLOCK, set(SIGNALS))
    work = tempfile.mkdtemp(prefix=".verifypass-", dir=os.path.dirname(os.path.abspath(a.pkpass)))
    _WORKDIRS.append(work)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, set(SIGNALS))
    pk = os.path.join(work, "pass")  # untrusted zip contents live apart from our signer/root/wwdr files
    os.mkdir(pk)
    if a.no_chain:
        print("WARN --no-chain: trust chain NOT checked; signature math only. Do not treat this pass as trusted.")
    try:
        with zipfile.ZipFile(a.pkpass) as z:
            names = z.namelist()
            check(all("/" not in n and n not in ("", ".", "..") for n in names) and len(names) == len(set(names)),
                  f"flat archive, no duplicates, {len(names)} files: {', '.join(sorted(names))}")
            z.extractall(pk)
        for req in ("pass.json", "manifest.json", "signature", "icon.png"):
            check(req in names, f"has {req}")
        man = json.load(open(os.path.join(pk, "manifest.json")))
        payload = [n for n in names if n not in ("manifest.json", "signature")]
        check(sorted(man) == sorted(payload), "manifest lists exactly the payload files")
        bad = [n for n in man if os.path.exists(os.path.join(pk, n)) and
               hashlib.sha1(open(os.path.join(pk, n), "rb").read()).hexdigest() != man[n]]
        check(not bad, f"manifest SHA-1 hashes match ({len(man)} files){'; mismatched: ' + ', '.join(bad) if bad else ''}")

        sig, mpath = os.path.join(pk, "signature"), os.path.join(pk, "manifest.json")
        signer = os.path.join(work, "signer.pem")
        rc, _, err = run("openssl", "smime", "-verify", "-binary", "-inform", "DER", "-in", sig, "-content", mpath,
                         "-noverify", "-signer", signer, "-out", os.devnull)
        check(rc == 0, "CMS signature over manifest.json verifies (-noverify: math only)" + (f": {err.strip()}" if rc else ""))
        rc, certs, _ = run("openssl", "pkcs7", "-inform", "DER", "-in", sig, "-print_certs", "-noout")
        subjects = [l.split("=", 1)[1].strip() for l in certs.splitlines() if l.startswith("subject")]
        print(f"INFO embedded certs: {subjects}")
        rc, sattrs, _ = run("openssl", "cms", "-cmsout", "-print", "-inform", "DER", "-in", sig, "-noout")
        check("signingTime" in sattrs, "signature carries signingTime attribute")
        have_signer = os.path.exists(signer)

        if a.cert:
            want = hashlib.sha256(der_bytes(a.cert)).hexdigest()
            got = hashlib.sha256(der_bytes(signer)).hexdigest() if have_signer else None
            check(got == want, f"signer cert == --cert (DER SHA-256 {want[:16]}…{'' if got == want else f' vs {str(got)[:16]}…'})")
        else:
            print("INFO no --cert given: signer cert NOT compared to pass.cer")

        if a.root:
            pins = {"root": (a.root, APPLE_ROOT_SHA256), "wwdr": (a.wwdr, WWDR_G4_SHA256)}
            for name, (path, pin) in pins.items():
                h = hashlib.sha256(der_bytes(path)).hexdigest()
                if a.test_unpinned_chain:
                    print(f"WARN {name} pin NOT enforced (--test-unpinned-chain): {h[:16]}…")
                else:
                    check(h == pin, f"{name} cert matches Apple's pinned SHA-256 ({pin[:16]}…)")
            root, wwdr = os.path.join(work, "root.pem"), os.path.join(work, "wwdr.pem")
            write_pem(a.root, root); write_pem(a.wwdr, wwdr)
            rc, _, err = run("openssl", "smime", "-verify", "-binary", "-inform", "DER", "-in", sig, "-content", mpath,
                             "-CAfile", root, *NO_DEFAULT_TRUST, "-certfile", wwdr, "-purpose", "any",
                             "-out", os.devnull)
            check(rc == 0, "signature + chain verify (pinned trust only, -no-CApath/-no-CAfile/-no-CAstore)"
                  + (f": {err.strip()}" if rc else ""))
            # signer must chain to the supplied WWDR and root, with nothing else trusted
            if have_signer:
                rc, out, err = run("openssl", "verify", *NO_DEFAULT_TRUST, "-CAfile", root, "-untrusted", wwdr,
                                   "-purpose", "any", signer)
                check(rc == 0, "signer cert: openssl verify -CAfile ROOT -untrusted WWDR" + (f": {err.strip()}" if rc else ""))
                iss, wsub = dn(signer, "issuer"), dn(wwdr, "subject")
                check(iss is not None and iss == wsub, f"signer issuer DN == supplied WWDR subject DN exactly")
                check(iss == WWDR_G4_DN, f"signer issuer DN is exactly '{WWDR_G4_DN}' (got '{iss}')")
            rc, _, _ = run("openssl", "x509", "-in", signer, "-noout", "-checkend", "0")
            check(have_signer and rc == 0, "signer cert not expired")
        else:
            print("WARN no chain check (--no-chain): signer NOT verified against Apple WWDR G4 / Root")

        pj = json.load(open(os.path.join(pk, "pass.json"), encoding="utf-8"))
        attrs = {}
        if have_signer:
            rc, subj, _ = run("openssl", "x509", "-in", signer, "-noout", "-subject", "-nameopt", "sep_multiline,sname,utf8")
            attrs = dict(l.strip().partition("=")[::2] for l in subj.splitlines()[1:])
        check(pj.get("passTypeIdentifier") == attrs.get("UID"), f"passTypeIdentifier == signer UID ({attrs.get('UID')})")
        check(pj.get("teamIdentifier") == attrs.get("OU"), f"teamIdentifier == signer OU ({attrs.get('OU')})")
        check(pj.get("formatVersion") == 1 and "generic" in pj, "formatVersion 1, generic style")
        for k in ("webServiceURL", "authenticationToken"):
            check(k not in pj, f"no {k}")
        if a.card:
            want_sp = bool(json.load(open(a.card)).get("sharingProhibited", True))
            src = "card"
        else:
            want_sp, src = True, "makepass default"
        check(pj.get("sharingProhibited", False) is want_sp,
              f"sharingProhibited == {str(want_sp).lower()} ({src})")
        print(f"INFO barcode: {'yes' if ('barcodes' in pj or 'barcode' in pj) else 'none'}")
        redact = None if a.show_except is None else set(filter(None, a.show_except.split(",")))
        for sec, fl in pj["generic"].items():
            for f in fl:
                v = str(f.get("value", ""))
                shown = repr(v) if (redact is not None and f["key"] not in redact) else f"<{len(v)} chars>"
                print(f"FIELD {sec}.{f['key']} [{f.get('label', '')}] = {shown}")
    finally:
        _cleanup()
    if not ok_all:
        print("RESULT FAILED")
    elif a.no_chain:
        print("RESULT OK-UNTRUSTED (--no-chain: trust chain NOT verified; NOT proof the pass is Apple-signed)")
    else:
        print("RESULT OK")
    sys.exit(1 if not ok_all else (3 if a.no_chain else 0))


if __name__ == "__main__":
    main()
