#!/usr/bin/env bash
# fetch-apple-certs.sh KEYDIR - Easy Wallet Card: download Apple's WWDR G4 intermediate and Apple Root CA into
# KEYDIR (only if missing) and check both against pinned SHA-256 values. Exit 0 only if both match.
set -euo pipefail
umask 077
[ $# -eq 1 ] || { echo "usage: fetch-apple-certs.sh KEYDIR" >&2; exit 2; }
DIR=$1
WWDR_SHA256=ea4757885538dd8cb59ff4556f676087d83c85e70902c122e42c0808b5bce14c
ROOT_SHA256=b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
mkdir -p "$DIR"

fetch() {  # fetch NAME URL PIN
  local f="$DIR/$1" new=0
  if [ ! -f "$f" ]; then
    curl -fsS --proto =https --tlsv1.2 -o "$f.part" "$2"
    mv -f -- "$f.part" "$f"; new=1
  fi
  chmod 600 "$f"
  local got; got=$(sha256 "$f")
  if [ "$got" != "$3" ]; then
    [ "$new" = 1 ] && rm -f -- "$f"
    echo "fetch-apple-certs: $f SHA-256 $got does not match pinned $3" >&2
    exit 1
  fi
  echo "fetch-apple-certs: $1 OK (SHA-256 matches pin)"
}
fetch AppleWWDRCAG4.cer https://www.apple.com/certificateauthority/AppleWWDRCAG4.cer "$WWDR_SHA256"
fetch AppleIncRootCertificate.cer https://www.apple.com/appleca/AppleIncRootCertificate.cer "$ROOT_SHA256"
