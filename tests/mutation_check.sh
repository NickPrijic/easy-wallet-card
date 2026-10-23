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
  cp -a "$REPO"/.gitignore "$REPO"/finish.sh "$REPO"/makepass.py "$REPO"/verifypass.py "$REPO"/fetch-apple-certs.sh "$REPO"/cards "$REPO"/tests "$T/m/"
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
      echo "mutant killed: $name -> $t FAILED as expected: $(grep -m1 -E 'AssertionError|Error:' "$T/log" | cut -c1-160)"
    fi
  done
}
mutant "old 9> lock file" finish.sh 'exec 9<"$OUTDIR"' 'exec 9>"$OUTDIR/.lock"' \
  test_lock_symlink_to_outside_file_untouched test_lock_symlink_to_missing_path_creates_nothing
mutant "old 9>> lock file" finish.sh 'exec 9<"$OUTDIR"' 'exec 9>>"$OUTDIR/.lock"' \
  test_lock_symlink_to_missing_path_creates_nothing
mutant "--no-chain exits 0" verifypass.py '(3 if (a.no_chain or a.test_unpinned_chain) else 0)' \
  '(3 if a.test_unpinned_chain else 0)' test_no_chain_exits_3
mutant "cards/ not ignored" .gitignore $'cards/*\n' '' test_gitignore_keeps_private_files_out
mutant "temp dirs not ignored" .gitignore $'.makepass-*/\n' '' test_gitignore_keeps_private_files_out
mutant "CSR/crt/der/pfx not ignored" .gitignore $'*.certSigningRequest\n' '' test_gitignore_keeps_private_files_out
mutant "--test-unpinned-chain exits 0" verifypass.py '(3 if (a.no_chain or a.test_unpinned_chain) else 0)' \
  '(3 if a.no_chain else 0)' test_unpinned_verify_is_never_plain_ok
mutant "test build installed at --out" finish.sh 'TARGET=${OUT%.pkpass}.TEST-UNPINNED.pkpass ;;' 'TARGET=$OUT ;;' \
  test_finish_unpinned_never_installed_at_out
mutant "finish key check follows symlinks" finish.sh \
  $'[ ! -L "$KEY" ] || die "$KEY is a symlink; it must be the real key file"\npython3 -c \'import os,stat,sys; st=os.lstat(sys.argv[1]); sys.exit(0 if stat.S_ISREG(st.st_mode) and not st.st_mode & 0o077 else 1)\'' \
  $'python3 -c \'import os,sys; sys.exit(1 if os.stat(sys.argv[1]).st_mode & 0o077 else 0)\'' \
  test_finish_refuses_symlinked_key
mutant "makepass key check follows symlinks" makepass.py \
  $'    if os.path.islink(a.key):\n        die(f"key file {a.key} is a symlink; point --key at the real file")\n    st = os.lstat(a.key)\n    if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:' \
  $'    st = os.stat(a.key)\n    if st.st_mode & 0o077:' test_makepass_refuses_symlinked_key
mutant "dash paths passed through" finish.sh $'-*) printf \'./%s\' "$1" ;;' $'-*) printf \'%s\' "$1" ;;' \
  test_finish_leading_dash_paths
exit $status
