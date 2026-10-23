# AGENTS.md: making an Apple Wallet pass with Easy Wallet Card

This is a runbook for an AI agent (or a person) helping someone turn a card, such as an insurance or membership
card, into an Apple Wallet pass. Follow the steps in order. Commands run from the repo root.
`README.md` has the background on what each tool checks.

## Hard rules (read first, they apply to every step)
1. Never commit or print keys, certificates, CSRs, real card files or `.pkpass` files. That means no `cat`,
   `head`, `less`, `base64`, `xxd` or `openssl ... -text` on `keys/*`, no pasting them into chat, and no copying
   them outside this machine. Checking a file exists or its mode (`ls -l`) is fine.
2. Never paste member IDs, group IDs, policy numbers or other card values into chat, logs, commit messages or
   tool output you show. Refer to fields by their label ("member ID: 12 characters"). `verifypass.py` prints
   value lengths only. Don't pass `--show-except`.
3. Before any commit, run `git status` and `git diff --cached --name-only`. Confirm nothing under `keys/` or
   `out/`, no `.pkpass`, `.key`, `.cer`, `.csr`, `.certSigningRequest`, and no card except
   `cards/sample-card.json`, `cards/sample-logo.png` and the unchanged files in `cards/examples/` is staged. Most of these are in `.gitignore`, but check
   anyway (for example `git add -f` bypasses it). You don't normally need to commit anything to make a pass.
4. Never deliver a pass unless `verifypass.py` printed `RESULT OK` and exited 0 (step 8). A test build or an
   untrusted result is never delivered.
5. Keep private files private: `keys/` mode 700, `keys/pass-signing.key` mode 600. The tools refuse a key that
   group or others can read, a key that is a symlink, or a key reached through a symlinked directory.

## STOP AND ASK THE PERSON
Stop and ask, then wait for the answer, at each of these points. Don't guess and don't work around them.
- **Apple Developer sign-in, 2FA and payment** (step 3): only the person signs in to developer.apple.com. You never
  handle their Apple ID password, a one-time code, or a credit card.
- **Card details** (step 5): the person provides every real value (member ID, group, names, dates). Ask for them.
  Don't invent values or reuse the sample's.
- **Recipient email / delivery** (step 9): the person chooses how the pass reaches the phone. You don't send mail
  or AirDrop until they name the recipient and approve.

### 1. Prerequisites
```
command -v python3 openssl flock git curl
python3 -c 'import PIL; print("Pillow", PIL.__version__)'
```
Python 3, Pillow, openssl, flock, git and curl are required. On macOS, `brew install flock` if needed, and use
OpenSSL 3 (Homebrew `openssl@3`) rather than the system LibreSSL when possible.

### 2. Create the signing key and CSR (once per machine)
```
mkdir -p keys && chmod 700 keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/pass-signing.key
chmod 600 keys/pass-signing.key
openssl req -new -key keys/pass-signing.key -out keys/pass-signing.csr -subj "/CN=Easy Wallet Card"
chmod 600 keys/pass-signing.csr
ls -l keys
```
Never overwrite an existing `keys/pass-signing.key`. If it's already there, reuse it and its CSR.

### 3. STOP: Pass Type ID certificate on developer.apple.com
Ask the person to sign in at https://developer.apple.com/account/resources/certificates/list, create a
**Pass Type ID** certificate from `keys/pass-signing.csr`, and save the downloaded `.cer` as `keys/pass.cer`
(mode 600). You do not sign in, enter 2FA, or pay. Wait until `keys/pass.cer` exists.

### 4. Fetch Apple's WWDR G4 and Root CA (pinned)
```
./fetch-apple-certs.sh keys
```
Exit codes: 0 = the two certs are present and match the pinned SHA-256 values. Any other code means failed;
stop. (curl exit 6 = DNS failure, 22 = HTTP error.)

### 5. STOP: write the card JSON
Copy the sample, then fill in the person's values. Prefer that they edit the file themselves rather than
pasting member IDs into chat:
```
cp cards/sample-card.json cards/my-card.json
cp cards/sample-logo.png cards/my-logo.png
```
Ask for every real value. Don't invent values or reuse the sample's or an example's. Prefer a template from
`cards/sample-card.json` or `cards/examples/` (copy to `cards/` first; never deliver an example unedited). Put a fresh random UUID in
`serialNumber` (`python3 -c 'import uuid; print(uuid.uuid4())'`). Validate with
`python3 -m json.tool cards/my-card.json` and confirm `git check-ignore -q cards/my-card.json`.

### 6. Build, verify and install with finish.sh
```
./finish.sh --card cards/my-card.json --logo cards/my-logo.png --keys keys --out out/my-card.pkpass
```
Exit codes for `finish.sh`:
| code | meaning | what to do |
|---|---|---|
| 0 | READY — pinned, verified, installed at OUT | continue to step 8 / 9 |
| 1 | failed (missing files, pin mismatch, verify failed, …) | stop; read the error |
| 2 | usage error | fix the command |
| 4 | TEST BUILD (`--test-unpinned-chain`) — not Apple-verified, not at OUT | never deliver |
| any other (including 129–143 for signals) | failed | stop |

### 7. Optional: the manual build
You normally don't need this, because finish.sh already built and verified the pass. The manual equivalent
(no verification, no install step; always follow it with step 8) is
```
./makepass.py --card cards/my-card.json --logo cards/my-logo.png \
  --cert keys/pass.cer --key keys/pass-signing.key --wwdr keys/AppleWWDRCAG4.cer \
  --out out/manual.pkpass
```
Always follow a manual build with step 8.

### 8. Confirm RESULT OK
```
./verifypass.py out/my-card.pkpass --root keys/AppleIncRootCertificate.cer \
  --wwdr keys/AppleWWDRCAG4.cer --cert keys/pass.cer --card cards/my-card.json
```
Exit codes for `verifypass.py`:
| code | meaning | what to do |
|---|---|---|
| 0 | RESULT OK | only this is deliverable |
| 1 | RESULT FAILED | stop |
| 2 | usage error | fix the command |
| 3 | RESULT OK-UNTRUSTED (with `--no-chain`) or RESULT OK-TEST-UNPINNED (with `--test-unpinned-chain`) | the pass is NOT proven Apple-signed; never deliver. Rerun without those flags against the real Apple certs. |
| any other | failed | stop |

For a test build, the matching check is
`./verifypass.py out/my-card.TEST-UNPINNED.pkpass --root ... --wwdr ... --cert ... --card ... --test-unpinned-chain`.
It exits 3 with `RESULT OK-TEST-UNPINNED` at best. That's still not deliverable.

### 9. STOP: deliver so the person taps Add to Wallet
Ask the person which email address should receive the pass (or whether they'd rather use AirDrop). Then either:
- **Email, sent by the person:** they attach `out/my-card.pkpass` to an email to themselves (or the recipient) and
  open it in **Apple Mail** on the iPhone. Tapping the attachment shows the pass with **Add**. Some webmail apps
  don't offer Add to Wallet, so Apple Mail is the safe choice.
- **Email, sent by you:** only if you have a mail tool, and only after the person approves the exact recipient,
  subject, body and attachment.
- **AirDrop** from a Mac: AirDrop `out/my-card.pkpass` to the iPhone and tap **Add**.

Don't upload the pass to a file-sharing site, paste it into chat, or commit it. After it's on the phone,
`out/my-card.pkpass` can stay in `out/` (ignored, mode 600).

### 10. Before any commit
```
git status
git diff --cached --name-only
```
Nothing under `keys/` or `out/`, no `*.pkpass`, `*.key`, `*.cer`, `*.csr`, and no card other than the two
samples and the unchanged `cards/examples/` templates. If anything like that is staged, unstage it (`git restore --staged <path>`) and tell the person.
