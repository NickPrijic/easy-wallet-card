#!/usr/bin/env python3
"""makepass.py - Easy Wallet Card: build a signed Apple Wallet .pkpass (generic style) from a card JSON + logo.

Python 3 stdlib + Pillow (image resizing) + the openssl CLI. See README.md.
Never prints field values: card data can hold member/policy IDs.
"""
import argparse, atexit, hashlib, json, os, re, shutil, signal, subprocess, sys, tempfile, zipfile

FORBIDDEN = ("webServiceURL", "authenticationToken")
BARCODE_FORMATS = {"PKBarcodeFormatQR", "PKBarcodeFormatPDF417", "PKBarcodeFormatAztec", "PKBarcodeFormatCode128"}
SECTIONS = {"header": "headerFields", "primary": "primaryFields", "secondary": "secondaryFields",
            "auxiliary": "auxiliaryFields", "back": "backFields"}


_WORKDIRS = []


def _cleanup():
    while _WORKDIRS:
        shutil.rmtree(_WORKDIRS.pop(), ignore_errors=True)


def _on_signal(signum, _frame):
    _cleanup()
    # re-raise default behaviour so the exit status reflects the signal
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


def install_cleanup():
    """Remove .makepass-* temp dirs on normal exit, errors, and SIGINT/SIGTERM/SIGHUP/SIGQUIT.
    (SIGKILL cannot be caught; finish.sh sweeps stale .makepass-* dirs.)"""
    atexit.register(_cleanup)
    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
        signal.signal(s, _on_signal)


def die(msg):
    print(f"makepass: error: {msg}", file=sys.stderr)
    sys.exit(1)


def openssl(*args, capture=False):
    r = subprocess.run(["openssl", *args], stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                       stderr=subprocess.PIPE, text=True)
    if r.returncode != 0:
        die(f"openssl {args[0]} failed: {r.stderr.strip()[:500]}")
    return r.stdout if capture else None


def cert_to_pem(src, dst):
    """Accept DER (.cer from Apple) or PEM; write PEM (public cert only)."""
    with open(src, "rb") as f:
        head = f.read(64)
    form = "PEM" if b"-----BEGIN" in head else "DER"
    openssl("x509", "-inform", form, "-in", src, "-out", dst)


def cert_ids(pem):
    """passTypeIdentifier = subject UID, teamIdentifier = subject OU."""
    out = openssl("x509", "-in", pem, "-noout", "-subject", "-nameopt", "sep_multiline,sname,utf8", capture=True)
    attrs = {}
    for line in out.splitlines()[1:]:
        k, _, v = line.strip().partition("=")
        attrs.setdefault(k, []).append(v)
    uid, ou = attrs.get("UID", []), attrs.get("OU", [])
    if len(uid) != 1 or len(ou) != 1:
        die(f"signer cert subject must carry exactly one UID and one OU (got UID x{len(uid)}, OU x{len(ou)})")
    pti, team = uid[0], ou[0]
    if not pti.startswith("pass."):
        die(f"cert UID '{pti}' is not a Pass Type ID (must start with 'pass.')")
    if not re.fullmatch(r"[A-Z0-9]{10}", team):
        print(f"makepass: WARNING: teamIdentifier '{team}' is not a 10-char Apple Team ID (test cert?)", file=sys.stderr)
    return pti, team


def fields(items, section):
    out = []
    seen = set()
    for i, f in enumerate(items or []):
        if not isinstance(f, dict) or not {"key", "value"} <= f.keys():
            die(f"{section}[{i}] needs at least 'key' and 'value'")
        if f["key"] in seen:
            die(f"duplicate field key '{f['key']}' in {section}")
        seen.add(f["key"])
        allowed = {"key", "label", "value", "textAlignment", "dateStyle", "timeStyle", "isRelative",
                   "numberStyle", "currencyCode", "dataDetectorTypes", "attributedValue", "changeMessage"}
        bad = set(f) - allowed
        if bad:
            die(f"{section}[{i}] has unsupported keys {sorted(bad)}")
        out.append(dict(f))
    return out


def build_pass_json(card, pti, team):
    for k in ("description", "organizationName", "serialNumber"):
        if not card.get(k):
            die(f"card JSON missing '{k}'")
    for k in FORBIDDEN:
        if k in card:
            die(f"card JSON must not set {k} (no web service / no hosting)")
    generic = {}
    for src, dst in SECTIONS.items():
        fl = fields(card.get(src), src)
        if fl:
            generic[dst] = fl
    allkeys = [f["key"] for v in generic.values() for f in v]
    if len(allkeys) != len(set(allkeys)):
        die("field keys must be unique across all sections")
    if "primaryFields" not in generic:
        die("card JSON needs at least one 'primary' field")
    colors = card.get("colors", {})
    pj = {
        "formatVersion": 1,
        "passTypeIdentifier": pti,
        "teamIdentifier": team,
        "serialNumber": str(card["serialNumber"]),
        "organizationName": card["organizationName"],
        "description": card["description"],
        "generic": generic,
        "sharingProhibited": bool(card.get("sharingProhibited", True)),
    }
    if card.get("logoText"):
        pj["logoText"] = card["logoText"]
    for ck, pk in (("background", "backgroundColor"), ("foreground", "foregroundColor"), ("label", "labelColor")):
        if colors.get(ck):
            if not re.fullmatch(r"rgb\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*\)", colors[ck]):
                die(f"colors.{ck} must look like rgb(r,g,b)")
            pj[pk] = colors[ck]
    bc = card.get("barcode")
    if bc:  # optional; default is no barcode
        if bc.get("format") not in BARCODE_FORMATS or not bc.get("message"):
            die(f"barcode needs 'message' and 'format' in {sorted(BARCODE_FORMATS)}")
        b = {"format": bc["format"], "message": str(bc["message"]),
             "messageEncoding": bc.get("messageEncoding", "iso-8859-1")}
        if bc.get("altText"):
            b["altText"] = bc["altText"]
        pj["barcodes"] = [b]
        if b["format"] != "PKBarcodeFormatCode128":
            pj["barcode"] = b  # legacy key for iOS < 9
    return pj


def parse_rgb(s, default=(255, 255, 255)):
    m = re.fullmatch(r"rgb\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)", s or "")
    return tuple(int(x) for x in m.groups()) if m else default


def make_images(logo, icon, stage, bg):
    try:
        from PIL import Image
    except ImportError:
        die("Pillow is required for image resizing (python3 -m pip install pillow)")

    def fit(img, w, h):
        im = img.copy()
        im.thumbnail((w, h), Image.LANCZOS)
        return im

    def square(img, side):
        im = fit(img, side, side)
        canvas = Image.new("RGBA", (side, side), bg + (255,))
        canvas.alpha_composite(im, ((side - im.width) // 2, (side - im.height) // 2))
        return canvas

    lg = Image.open(logo).convert("RGBA")
    ic = Image.open(icon).convert("RGBA") if icon else lg
    out = {}
    for scale, suffix in ((1, ""), (2, "@2x"), (3, "@3x")):
        out[f"logo{suffix}.png"] = fit(lg, 160 * scale, 50 * scale)
        out[f"icon{suffix}.png"] = square(ic, 29 * scale)
    for name, im in out.items():
        im.save(os.path.join(stage, name), "PNG", optimize=True)
    return sorted(out)


def sha1(path):
    with open(path, "rb") as f:
        return hashlib.sha1(f.read()).hexdigest()


def main():
    ap = argparse.ArgumentParser(allow_abbrev=False, description="Easy Wallet Card: build a signed generic Apple Wallet .pkpass from card JSON + logo.")
    ap.add_argument("--card", required=True, help="card JSON (see cards/sample-card.json)")
    ap.add_argument("--logo", required=True, help="logo image; resized to logo.png/@2x/@3x (and icon if no --icon)")
    ap.add_argument("--icon", help="optional square-ish image for icon.png/@2x/@3x")
    ap.add_argument("--cert", required=True, help="Pass Type ID certificate (.cer DER or PEM)")
    ap.add_argument("--key", required=True, help="private key path; passed to openssl by path only")
    ap.add_argument("--wwdr", required=True, help="Apple WWDR G4 intermediate (.cer DER or PEM)")
    ap.add_argument("--out", required=True, help="output .pkpass path (written mode 600)")
    a = ap.parse_args()

    for p in (a.card, a.logo, a.cert, a.key, a.wwdr) + ((a.icon,) if a.icon else ()):
        if not os.path.isfile(p):
            die(f"not found: {p}")
    if os.stat(a.key).st_mode & 0o077:
        die(f"key file {a.key} is readable by group/others; chmod 600 it first")
    os.umask(0o077)
    with open(a.card) as f:
        card = json.load(f)

    outdir = os.path.dirname(os.path.abspath(a.out))
    os.makedirs(outdir, mode=0o700, exist_ok=True)
    install_cleanup()
    sigs = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT}
    signal.pthread_sigmask(signal.SIG_BLOCK, sigs)  # no window between mkdtemp and registration
    work = tempfile.mkdtemp(prefix=".makepass-", dir=outdir)  # never /tmp; same private dir as output
    _WORKDIRS.append(work)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, sigs)
    try:
        stage = os.path.join(work, "pass")
        os.mkdir(stage)
        certpem, wwdrpem = os.path.join(work, "signer.pem"), os.path.join(work, "wwdr.pem")
        cert_to_pem(a.cert, certpem)
        cert_to_pem(a.wwdr, wwdrpem)
        pti, team = cert_ids(certpem)

        pj = build_pass_json(card, pti, team)
        with open(os.path.join(stage, "pass.json"), "w", encoding="utf-8") as f:
            json.dump(pj, f, ensure_ascii=False, indent=2)
        images = make_images(a.logo, a.icon, stage, parse_rgb(card.get("colors", {}).get("background")))

        files = ["pass.json"] + images
        manifest = {n: sha1(os.path.join(stage, n)) for n in files}
        mpath = os.path.join(stage, "manifest.json")
        with open(mpath, "w") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
        openssl("smime", "-binary", "-sign", "-signer", certpem, "-inkey", a.key, "-certfile", wwdrpem,
                "-in", mpath, "-out", os.path.join(stage, "signature"), "-outform", "DER")

        tmpout = os.path.join(work, "out.pkpass")
        with zipfile.ZipFile(tmpout, "w", zipfile.ZIP_DEFLATED) as z:
            for n in files + ["manifest.json", "signature"]:
                z.write(os.path.join(stage, n), n)
        os.chmod(tmpout, 0o600)
        os.replace(tmpout, a.out)
    finally:
        _cleanup()

    nfields = sum(len(v) for v in pj["generic"].values())
    print(f"makepass: wrote {a.out} (mode 600)")
    print(f"makepass: passTypeIdentifier={pti} teamIdentifier={team} fields={nfields} "
          f"barcode={'yes' if 'barcodes' in pj else 'no'} files={len(files) + 2}")


if __name__ == "__main__":
    main()
