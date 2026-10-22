#!/usr/bin/env bash
# finish.sh - Easy Wallet Card: build a pass with makepass.py, verify it with verifypass.py, and only then move
# it into place. The private key is handed to openssl by path; its contents are never read or printed.
# The pass is built inside OUTDIR/.finish-*/ and renamed to OUT only if verifypass reports RESULT OK.
# Refuses to overwrite an existing OUT unless --force. Holds flock on OUTDIR/.lock for the whole run.
set -euo pipefail
umask 077
unset SSL_CERT_DIR SSL_CERT_FILE   # trust comes only from the pinned files in KEYDIR

usage() {
  cat >&2 <<'USAGE'
usage: finish.sh [--force] [--test-unpinned-chain] --card CARD.json --logo LOGO.png [--icon ICON.png]
                 --keys KEYDIR --out OUT.pkpass

Easy Wallet Card: build, verify, then install a signed Apple Wallet pass.
KEYDIR must hold pass.cer (Apple's Pass Type ID cert) and pass-signing.key (mode 600). The Apple WWDR G4 and
Apple Root CA certs (AppleWWDRCAG4.cer, AppleIncRootCertificate.cer) are fetched by fetch-apple-certs.sh if
missing and must match pinned SHA-256 values.
  --force                 rebuild even if OUT already exists
  --test-unpinned-chain   skip the Apple SHA-256 pins (throwaway test chains only)
Optional guards (environment): EXPECT_TEAM_ID, EXPECT_PASS_TYPE_ID must equal the cert's OU / UID.
USAGE
  exit 2
}

FORCE=0 UNPINNED=0 CARD= LOGO= ICON= KEYS= OUT=
while [ $# -gt 0 ]; do
  case $1 in
    --force) FORCE=1; shift ;;
    --test-unpinned-chain) UNPINNED=1; shift ;;
    --card|--logo|--icon|--keys|--out)
      [ $# -ge 2 ] || usage
      case $1 in --card) CARD=$2 ;; --logo) LOGO=$2 ;; --icon) ICON=$2 ;; --keys) KEYS=$2 ;; --out) OUT=$2 ;; esac
      shift 2 ;;
    -h|--help) usage ;;
    *) echo "finish: unknown argument: $1" >&2; usage ;;
  esac
done
[ -n "$CARD" ] && [ -n "$LOGO" ] && [ -n "$KEYS" ] && [ -n "$OUT" ] || usage

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CER=$KEYS/pass.cer KEY=$KEYS/pass-signing.key
WWDR=$KEYS/AppleWWDRCAG4.cer ROOT=$KEYS/AppleIncRootCertificate.cer
WWDR_DN='C=US,O=Apple Inc.,OU=G4,CN=Apple Worldwide Developer Relations Certification Authority'  # RFC2253 order
NO_DEFAULT_TRUST=(-no-CApath -no-CAfile -no-CAstore)

die() { echo "finish: $*" >&2; exit 1; }
sha256s() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; }
command -v flock >/dev/null 2>&1 || die "flock(1) is required (macOS: brew install flock)"
for f in "$CARD" "$LOGO" ${ICON:+"$ICON"}; do [ -f "$f" ] || die "not found: $f"; done
[ -f "$CER" ] || die "missing $CER (save Apple's downloaded pass.cer there)"
[ -f "$KEY" ] || die "missing $KEY"
python3 -c 'import os,sys; sys.exit(1 if os.stat(sys.argv[1]).st_mode & 0o077 else 0)' "$KEY" \
  || die "$KEY is readable by group/others; chmod 600 it first"

OUTDIR=$(dirname -- "$OUT")
[ -d "$OUTDIR" ] || mkdir -p -m 700 -- "$OUTDIR"

# One run at a time: an overlapping run fails fast and never sweeps a live run's temp dir.
exec 9>"$OUTDIR/.lock"
flock -n 9 || die "another finish.sh run holds the lock $OUTDIR/.lock; try again when it finishes"
if [ -e "$OUT" ] && [ "$FORCE" != 1 ]; then die "$OUT already exists; pass --force to rebuild"; fi

# Sweep stale temp dirs left by a killed run (SIGKILL can't be trapped). Safe only because we hold the lock.
for d in "$OUTDIR"/.makepass-* "$OUTDIR"/.verifypass-* "$OUTDIR"/.finish-*; do
  [ -e "$d" ] || continue
  echo "finish: removing stale $(basename -- "$d")"; rm -rf -- "$d"
done

TMPD=
trap '[ -z "$TMPD" ] || rm -rf -- "$TMPD"' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP; trap 'exit 131' QUIT
TMPD=$(mktemp -d "$OUTDIR/.finish-XXXXXX")

VERIFY_EXTRA=()
if [ "$UNPINNED" = 1 ]; then
  [ -f "$WWDR" ] && [ -f "$ROOT" ] || die "--test-unpinned-chain needs $WWDR and $ROOT"
  echo "finish: WARN --test-unpinned-chain: Apple SHA-256 pins NOT enforced (test chains only)"
  VERIFY_EXTRA=(--test-unpinned-chain)
else
  "$HERE/fetch-apple-certs.sh" "$KEYS"
fi

topem() { local f=DER; head -c 11 "$1" | grep -q -- '-----BEGIN' && f=PEM; openssl x509 -inform $f -in "$1" -out "$2"; }
topem "$CER" "$TMPD/pass.pem"; topem "$WWDR" "$TMPD/wwdr.pem"; topem "$ROOT" "$TMPD/root.pem"
issuer=$(openssl x509 -in "$TMPD/pass.pem" -noout -issuer -nameopt RFC2253); issuer=${issuer#issuer=}
wwdr_subj=$(openssl x509 -in "$TMPD/wwdr.pem" -noout -subject -nameopt RFC2253); wwdr_subj=${wwdr_subj#subject=}
echo "finish: $(openssl x509 -in "$TMPD/pass.pem" -noout -enddate)"
# Exact issuer DN (no substring matching), equal to the WWDR's subject...
[ "$issuer" = "$WWDR_DN" ] && [ "$wwdr_subj" = "$WWDR_DN" ] || die "issuer DN '$issuer' is not exactly '$WWDR_DN'"
# ...and the cert must chain to ONLY the supplied WWDR G4 + Apple Root (no system trust).
openssl verify "${NO_DEFAULT_TRUST[@]}" -CAfile "$TMPD/root.pem" -untrusted "$TMPD/wwdr.pem" -purpose any \
  "$TMPD/pass.pem" >/dev/null 2>"$TMPD/verify.err" \
  || die "pass.cer does not chain to WWDR G4 -> Apple Root: $(tr '\n' ' ' <"$TMPD/verify.err")"
echo "finish: pass.cer chains to WWDR G4 -> Apple Root CA (no system trust)"
openssl x509 -in "$TMPD/pass.pem" -noout -checkend 0 >/dev/null || die "cert expired"

subj_ml=$(openssl x509 -in "$TMPD/pass.pem" -noout -subject -nameopt sep_multiline,sname,utf8)
uid=$(sed -n 's/^ *UID=//p' <<<"$subj_ml"); ou=$(sed -n 's/^ *OU=//p' <<<"$subj_ml")
if [ -n "${EXPECT_TEAM_ID:-}" ] && [ "$ou" != "$EXPECT_TEAM_ID" ]; then
  die "cert team ID (OU) '$ou' is not EXPECT_TEAM_ID '$EXPECT_TEAM_ID', refusing"
fi
if [ -n "${EXPECT_PASS_TYPE_ID:-}" ] && [ "$uid" != "$EXPECT_PASS_TYPE_ID" ]; then
  die "cert Pass Type ID (UID) '$uid' is not EXPECT_PASS_TYPE_ID '$EXPECT_PASS_TYPE_ID', refusing"
fi

# Public-key match (only public keys are compared; the private key is passed by path)
a=$(openssl x509 -in "$TMPD/pass.pem" -noout -pubkey | openssl pkey -pubin -outform DER | sha256s)
b=$(openssl pkey -in "$KEY" -pubout -outform DER | sha256s)
[ "$a" = "$b" ] || die "pass.cer does not match pass-signing.key (was the CSR made from this key?)"
echo "finish: cert public key matches pass-signing.key"

UNVERIFIED="$TMPD/unverified.pkpass"     # inside TMPD: removed by the EXIT trap on any failure
"$HERE/makepass.py" --card "$CARD" --logo "$LOGO" ${ICON:+--icon "$ICON"} \
  --cert "$CER" --key "$KEY" --wwdr "$WWDR" --out "$UNVERIFIED"
if ! "$HERE/verifypass.py" "$UNVERIFIED" --root "$ROOT" --wwdr "$WWDR" --cert "$CER" --card "$CARD" \
     ${VERIFY_EXTRA[@]+"${VERIFY_EXTRA[@]}"}; then
  die "verification FAILED; unverified pass deleted, $OUT not written"
fi
chmod 600 "$UNVERIFIED"
mv -f -- "$UNVERIFIED" "$OUT"
echo "finish: READY $OUT ($(wc -c <"$OUT" | tr -d ' ') bytes, mode 600)"
