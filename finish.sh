#!/usr/bin/env bash
# finish.sh - Easy Wallet Card: build a pass with makepass.py, verify it with verifypass.py, and only then move
# it into place. finish.sh never opens the private key: it only lstat-checks the path (no symlinked file or
# parent dir), and makepass.py opens it once with O_NOFOLLOW, checks that fd, and hands it to openssl as
# /dev/fd/N (including for the cert/key public-key match). Its contents are never read or printed.
# The pass is built inside OUTDIR/.finish-*/ and renamed to OUT only if verifypass reports RESULT OK.
# Exit codes: 0 = READY (pinned, verified, installed at OUT), 1 = failed, 2 = usage error,
# 4 = TEST BUILD (--test-unpinned-chain): verified against a test chain only, left at OUT's name with
#     .TEST-UNPINNED inserted before .pkpass, never at OUT itself.
# Refuses to overwrite an existing OUT unless --force. Holds flock on OUT's directory itself for the whole run
# (opened read-only: no lock file is ever created, followed through a symlink, or truncated).
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
  --test-unpinned-chain   skip the Apple SHA-256 pins (throwaway test chains only). The pass is NOT installed
                          at OUT: it is left as OUT with .TEST-UNPINNED before .pkpass, and the exit code is 4.
Exit codes: 0 READY, 1 failed, 2 usage error, 4 TEST BUILD (not Apple-verified).
Paths that start with '-' are fine; they are passed on as ./-name.
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
# A relative path starting with '-' would be read as an option by openssl, head, mktemp or argparse.
dash() { case $1 in -*) printf './%s' "$1" ;; *) printf '%s' "$1" ;; esac; }
CARD=$(dash "$CARD") LOGO=$(dash "$LOGO") KEYS=$(dash "$KEYS") OUT=$(dash "$OUT")
[ -z "$ICON" ] || ICON=$(dash "$ICON")
if [ "$UNPINNED" = 1 ]; then
  case $OUT in *.pkpass) TARGET=${OUT%.pkpass}.TEST-UNPINNED.pkpass ;; *) TARGET=$OUT.TEST-UNPINNED.pkpass ;; esac
else
  TARGET=$OUT
fi

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CER=$KEYS/pass.cer KEY=$KEYS/pass-signing.key
WWDR=$KEYS/AppleWWDRCAG4.cer ROOT=$KEYS/AppleIncRootCertificate.cer
WWDR_DN='C=US,O=Apple Inc.,OU=G4,CN=Apple Worldwide Developer Relations Certification Authority'  # RFC2253 order
NO_DEFAULT_TRUST=(-no-CApath -no-CAfile -no-CAstore)

die() { echo "finish: $*" >&2; exit 1; }
command -v flock >/dev/null 2>&1 || die "flock(1) is required (macOS: brew install flock)"
for f in "$CARD" "$LOGO" ${ICON:+"$ICON"}; do [ -f "$f" ] || die "not found: $f"; done
[ -f "$CER" ] || die "missing $CER (save Apple's downloaded pass.cer there)"
[ -f "$KEY" ] || die "missing $KEY"
[ ! -L "$KEY" ] || die "$KEY is a symlink; it must be the real key file"
python3 -c 'import os,stat,sys; st=os.lstat(sys.argv[1]); sys.exit(0 if stat.S_ISREG(st.st_mode) and not st.st_mode & 0o077 else 1)' "$KEY" \
  || die "$KEY must be a regular file readable only by you; chmod 600 it first"
# No symlink anywhere on the key's path (e.g. a symlinked keys/ dir). Same check makepass.py runs; lstat only.
keyerr=$(python3 -B -c 'import sys; sys.path.insert(0, sys.argv[1]); import makepass
try: makepass.open_key(sys.argv[2], open_file=False)
except makepass.KeyRefused as e: print(e); sys.exit(1)' "$HERE" "$KEY" 2>&1) || die "${keyerr:-unsafe key path $KEY}"

OUTDIR=$(dirname -- "$OUT")
[ -d "$OUTDIR" ] || mkdir -p -m 700 -- "$OUTDIR"

# One run at a time. Lock the directory itself, opened read-only (never 9> / 9>>): nothing is created,
# followed or truncated. An overlapping run fails fast and never sweeps a live run's temp dir.
exec 9<"$OUTDIR"
flock -n 9 || die "another finish.sh run holds the lock on $OUTDIR; try again when it finishes"
if [ -e "$TARGET" ] && [ "$FORCE" != 1 ]; then die "$TARGET already exists; pass --force to rebuild"; fi

# Sweep stale temp dirs left by a killed run (SIGKILL can't be trapped). Safe only because we hold the lock.
for d in "$OUTDIR"/.makepass-* "$OUTDIR"/.verifypass-* "$OUTDIR"/.finish-*; do
  [ -e "$d" ] || continue
  echo "finish: removing stale $(basename -- "$d")"; rm -rf -- "$d"
done

TMPD=
trap '[ -z "$TMPD" ] || rm -rf -- "$TMPD"' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP; trap 'exit 131' QUIT
TMPD=$(mktemp -d -- "$OUTDIR/.finish-XXXXXX")

VERIFY_EXTRA=()
if [ "$UNPINNED" = 1 ]; then
  [ -f "$WWDR" ] && [ -f "$ROOT" ] || die "--test-unpinned-chain needs $WWDR and $ROOT"
  echo "finish: WARN --test-unpinned-chain: Apple SHA-256 pins NOT enforced (test chains only)"
  VERIFY_EXTRA=(--test-unpinned-chain)
else
  "$HERE/fetch-apple-certs.sh" "$KEYS"
fi

topem() { local f=DER; head -c 11 -- "$1" | grep -q -- '-----BEGIN' && f=PEM; openssl x509 -inform $f -in "$1" -out "$2"; }
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

# The cert/key public-key match runs inside makepass.py on its one O_NOFOLLOW fd: finish.sh never opens the key.
UNVERIFIED="$TMPD/unverified.pkpass"     # inside TMPD: removed by the EXIT trap on any failure
"$HERE/makepass.py" --card "$CARD" --logo "$LOGO" ${ICON:+--icon "$ICON"} \
  --cert "$CER" --key "$KEY" --wwdr "$WWDR" --out "$UNVERIFIED"
rc=0
"$HERE/verifypass.py" "$UNVERIFIED" --root "$ROOT" --wwdr "$WWDR" --cert "$CER" --card "$CARD" \
  ${VERIFY_EXTRA[@]+"${VERIFY_EXTRA[@]}"} || rc=$?
# Pinned builds need RESULT OK (exit 0). Test builds need RESULT OK-TEST-UNPINNED (exit 3), nothing else.
if [ "$UNPINNED" = 1 ]; then want=3; else want=0; fi
[ "$rc" = "$want" ] || die "verification FAILED (verifypass exit $rc); unverified pass deleted, $TARGET not written"
chmod 600 "$UNVERIFIED"
mv -f -- "$UNVERIFIED" "$TARGET"
size=$(wc -c <"$TARGET" | tr -d ' ')
if [ "$UNPINNED" = 1 ]; then
  echo "finish: TEST BUILD $TARGET ($size bytes, mode 600): UNPINNED, NOT Apple-verified, NOT installed at $OUT"
  exit 4
fi
echo "finish: READY $OUT ($size bytes, mode 600)"
