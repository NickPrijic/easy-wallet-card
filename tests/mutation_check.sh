#!/usr/bin/env bash
# mutation_check.sh - Easy Wallet Card: prove the tests catch the old behaviour.
# Copies the repo to a temp dir, re-introduces each old bug (a one-line edit, or a whole file restored from the
# last commit before the fix), and expects the matching tests to FAIL.
set -euo pipefail
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
T=$(mktemp -d); trap 'rm -rf -- "$T"' EXIT
status=0
setup() {
  rm -rf "$T/m"; mkdir "$T/m"
  cp -a "$REPO"/.gitignore "$REPO"/finish.sh "$REPO"/makepass.py "$REPO"/verifypass.py "$REPO"/fetch-apple-certs.sh "$REPO"/cards "$REPO"/tests "$T/m/"
}
run_tests() {  # run_tests NAME TEST...
  local name=$1 t; shift
  for t in "$@"; do
    if (cd "$T/m" && python3 -B -m unittest discover -s tests -k "$t" >"$T/log" 2>&1); then
      echo "MUTANT SURVIVED: $name ($t passed against the old behaviour)"; status=1
    else
      echo "mutant killed: $name -> $t FAILED as expected: $(grep -m1 -E 'AssertionError|Error:' "$T/log" | cut -c1-200)"
    fi
  done
}
oldfile() {  # oldfile NAME FILE GIT-REV TEST...: FILE as it was at GIT-REV, everything else current
  local name=$1 file=$2 rev=$3; shift 3
  setup
  git -C "$REPO" show "$rev:$file" >"$T/m/$file" || { echo "cannot read $rev:$file (no git history?)"; status=1; return; }
  run_tests "$name" "$@"
}
mutant() {  # mutant NAME FILE PYTHON-REPLACE-OLD PYTHON-REPLACE-NEW TEST...
  local name=$1 file=$2 old=$3 new=$4; shift 4
  setup
  python3 - "$T/m/$file" "$old" "$new" <<'PY'
import sys
p, old, new = sys.argv[1:]
s = open(p).read()
assert old in s, f"mutation anchor not found in {p}"
open(p, "w").write(s.replace(old, new))
PY
  run_tests "$name" "$@"
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
mutant "makepass key open follows symlinks" makepass.py \
  'os.O_RDONLY | os.O_NOFOLLOW | os.O_NOCTTY | os.O_NONBLOCK' 'os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK' \
  test_makepass_refuses_symlinked_key
mutant "dash paths passed through" finish.sh $'-*) printf \'./%s\' "$1" ;;' $'-*) printf \'%s\' "$1" ;;' \
  test_finish_leading_dash_paths
# NIC-59 (N2 symlinked key dir, N3 key reopened by path). PRE_N2N3 is the last commit before the fix.
PRE_N2N3=4cc6c52
# (finish.sh imports makepass.open_key, so the finish tests are checked against one-line makepass mutants below.)
oldfile "makepass before N2/N3" makepass.py "$PRE_N2N3" \
  test_makepass_refuses_symlinked_key_dir test_makepass_signs_with_opened_fd_when_key_swapped_mid_run
oldfile "finish.sh before N2/N3" finish.sh "$PRE_N2N3" \
  test_finish_refuses_symlinked_key_dir test_openssl_never_gets_the_key_path
mutant "symlinked key dir followed" makepass.py \
  'if stat.S_ISLNK(st.st_mode) and not _system_link(st):' 'if False:' \
  test_makepass_refuses_symlinked_key_dir test_finish_refuses_symlinked_key_dir
mutant "openssl signs with the key path" makepass.py \
  '"-inkey", key_arg(kfd),' '"-inkey", a.key,' \
  test_makepass_signs_with_opened_fd_when_key_swapped_mid_run test_finish_signs_with_opened_fd_when_key_swapped_mid_run \
  test_openssl_never_gets_the_key_path
mutant "pubkey match reopens the key by path" makepass.py \
  '"-in", key_arg(kfd), "-pubout"' '"-in", a.key, "-pubout"' test_openssl_never_gets_the_key_path
mutant "fd mode check dropped" makepass.py \
  $'    st = os.fstat(kfd)\n    if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:' \
  $'    st = os.fstat(kfd)\n    if False:' test_makepass_rejects_group_readable_key
# NIC-61 example cards: allowlist fake-data guards
mutant "example with a non-fictional phone" cards/examples/business-card.json '"555-0100"' '"555-2368"' \
  test_examples_hold_only_fake_data
mutant "example with a letter-prefixed ID" cards/examples/loyalty-card.json '"EXAMPLE00000001"' '"ABC123456789"' \
  test_examples_hold_only_fake_data
mutant "example with a non-example URL" cards/examples/loyalty-card.json 'https://example.com/rewards' 'https://acme-corp.com/rewards' \
  test_examples_hold_only_fake_data
mutant "example with a real Wi-Fi password" cards/examples/wifi-guest-card.json \
  'WIFI:T:WPA;S:ExampleGuest;P:not-a-real-password;;' 'WIFI:T:WPA;S:ExampleGuest;P:s3cret-real;;' \
  test_examples_hold_only_fake_data
mutant "medical disclaimer dropped" cards/examples/medical-card.json 'This is not a medical record and not medical advice.' 'Keep this current.' \
  test_examples_hold_only_fake_data
mutant "barcode message carries a real phone" cards/examples/business-card.json \
  '"message": "https://example.com/studio"' '"message": "555-2368"' \
  test_examples_hold_only_fake_data
exit $status
