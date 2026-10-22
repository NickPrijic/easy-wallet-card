#!/usr/bin/env bash
# mutation_check.sh - Easy Wallet Card: prove the lock and exit-code tests catch the old behaviour.
# Copies the repo to a temp dir, re-introduces each old bug, and expects the matching tests to FAIL.
set -euo pipefail
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
T=$(mktemp -d); trap 'rm -rf -- "$T"' EXIT
status=0
mutant() {  # mutant NAME FILE PYTHON-REPLACE-OLD PYTHON-REPLACE-NEW TEST...
  local name=$1 file=$2 old=$3 new=$4; shift 4
  rm -rf "$T/m"; mkdir "$T/m"
  cp -a "$REPO"/finish.sh "$REPO"/makepass.py "$REPO"/verifypass.py "$REPO"/fetch-apple-certs.sh "$REPO"/cards "$REPO"/tests "$T/m/"
  python3 - "$T/m/$file" "$old" "$new" <<'PY'
import sys
p, old, new = sys.argv[1:]
s = open(p).read()
assert old in s, f"mutation anchor not found in {p}"
open(p, "w").write(s.replace(old, new))
PY
  for t in "$@"; do
    if (cd "$T/m" && python3 -m unittest discover -s tests -k "$t" >"$T/log" 2>&1); then
      echo "MUTANT SURVIVED: $name ($t passed against the old behaviour)"; status=1
    else
      echo "mutant killed: $name -> $t FAILED as expected"
    fi
  done
}
mutant "old 9> lock file" finish.sh 'exec 9<"$OUTDIR"' 'exec 9>"$OUTDIR/.lock"' \
  test_lock_symlink_to_outside_file_untouched test_lock_symlink_to_missing_path_creates_nothing
mutant "old 9>> lock file" finish.sh 'exec 9<"$OUTDIR"' 'exec 9>>"$OUTDIR/.lock"' \
  test_lock_symlink_to_missing_path_creates_nothing
mutant "--no-chain exits 0" verifypass.py '(3 if a.no_chain else 0)' '0' test_no_chain_exits_3
exit $status
