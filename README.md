# Easy Wallet Card

If you are an AI agent, start with [`AGENTS.md`](AGENTS.md).

Easy Wallet Card turns a small JSON file and a logo into a signed Apple Wallet pass (`.pkpass`, generic style),
for example an insurance or membership card you want on your phone.
It has no web service, no hosting, no `webServiceURL`/`authenticationToken`, and uses no third-party service.

Easy Wallet Card is not affiliated with or endorsed by Apple or any insurer.

Needs Python 3, Pillow (`python3 -m pip install pillow`), the `openssl` CLI, `curl`, and `flock`
(Linux: util-linux; macOS: `brew install flock`). `make` is only needed for the tests.

## 1. Get a Pass Type ID certificate
Signing a pass that iPhones accept needs an Apple Developer Program membership.
1. Make a private key and a certificate signing request (keep the key private, mode 600):
   ```
   mkdir -p keys && chmod 700 keys
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/pass-signing.key
   chmod 600 keys/pass-signing.key
   openssl req -new -key keys/pass-signing.key -out keys/pass-signing.csr -subj "/CN=Easy Wallet Card"
   ```
2. In the Apple Developer site, open Certificates, Identifiers & Profiles. Under Identifiers, register a
   **Pass Type ID** such as `pass.com.yourname.card`.
3. Under Certificates, create a **Pass Type ID Certificate** for that ID and upload `keys/pass-signing.csr`.
4. Download the certificate and save it as `keys/pass.cer`.
5. Fetch Apple's WWDR G4 intermediate and Apple Root CA. Both are checked against pinned SHA-256 values:
   ```
   ./fetch-apple-certs.sh keys
   ```

`keys/`, `out/`, your own cards (everything in `cards/` except the two samples), keys, certs, CSRs, passes and
temp dirs are in `.gitignore`. Never commit them.

## 2. Make your card
Copy `cards/sample-card.json`, edit the values, and use your own logo.

| key | meaning |
|---|---|
| `description`, `organizationName`, `serialNumber` | required. Use a random UUID for the serial. Don't derive it from an ID. |
| `colors.background/foreground/label` | optional, `rgb(r,g,b)` |
| `header`, `primary`, `secondary`, `auxiliary` | front fields: lists of `{key, label, value}`. At least one `primary` is required. |
| `back` | back fields. Phone numbers and URLs become tappable on the device. |
| `barcode` | optional. `{format: PKBarcodeFormatQR, PDF417, Aztec or Code128, message, altText}` |
| `logoText`, `sharingProhibited` | optional. Sharing is prohibited by default. |

Field keys must be unique across all sections. `--logo` is fitted into logo.png at 160x50 points, with @2x and
@3x versions. `--icon` (or the logo, if no icon is given) is centered on a square for icon.png at 29x29.

## 3. Build and verify
The easy way builds, verifies, and only then moves the pass into place:
```
./finish.sh --card cards/my-card.json --logo cards/my-logo.png [--icon cards/my-mark.png] --keys keys --out out/my-card.pkpass
```
- It checks the Apple certs' pinned SHA-256, requires the cert's issuer DN to be exactly Apple's WWDR G4,
  runs `openssl verify -no-CApath -no-CAfile -no-CAstore` against only those two certs, and checks that the
  cert isn't expired and matches your key (that public-key check runs inside makepass.py on its one open of the key).
- Optional guards: set `EXPECT_TEAM_ID` and/or `EXPECT_PASS_TYPE_ID` and it refuses a cert whose OU / UID
  don't match. Handy if you have more than one Apple team.
- It builds inside `out/.finish-*/` and renames the pass to `--out` only if `verifypass.py` reports RESULT OK.
  On any failure or on SIGINT, SIGTERM, SIGHUP or SIGQUIT the temp dir is removed. A SIGKILL can't be caught,
  so stale `.makepass-*`, `.verifypass-*` and `.finish-*` dirs are swept at the next start.
- It won't overwrite an existing pass unless you pass `--force`.
- `--test-unpinned-chain` is for throwaway test chains only. Such a build is never installed at `--out`: it is
  left next to it with `.TEST-UNPINNED` before `.pkpass` (for example `out/my-card.TEST-UNPINNED.pkpass`),
  and finish.sh exits 4 with `TEST BUILD … NOT Apple-verified`.
- Paths that start with `-` work; finish.sh passes them on as `./-name`.
- One run at a time: it holds `flock` on the output directory itself, opened read-only, so no lock file is ever
  created, followed through a symlink, or truncated. An overlapping run is refused.

Or run the two steps yourself:
```
./makepass.py --card cards/my-card.json --logo cards/my-logo.png --cert keys/pass.cer --key keys/pass-signing.key \
  --wwdr keys/AppleWWDRCAG4.cer --out out/my-card.pkpass
./verifypass.py out/my-card.pkpass --root keys/AppleIncRootCertificate.cer --wwdr keys/AppleWWDRCAG4.cer \
  --cert keys/pass.cer --card cards/my-card.json
```
AirDrop or email the `.pkpass` to your iPhone and tap it to add it to Wallet.

## What verifypass checks
- The zip is flat with no duplicates. The manifest lists exactly the payload files, and every SHA-1 matches.
- The CMS signature over manifest.json verifies, and it carries a signingTime.
- With `--root` and `--wwdr` (required unless `--no-chain`):
  - Both certs must match Apple's pinned SHA-256 values. `--test-unpinned-chain` turns off only this pin,
    for throwaway test chains, and prints a WARN.
  - The signature and the signer cert must chain signer → WWDR G4 → Apple Root using **only** those two files.
    `-no-CApath`, `-no-CAfile` and `-no-CAstore` are set and `SSL_CERT_DIR`/`SSL_CERT_FILE` are stripped, so a
    root planted in the system or environment trust store doesn't count.
  - The signer's issuer DN must exactly equal the supplied WWDR's subject DN and Apple's WWDR G4 DN.
- `--cert`: the embedded signer cert must be byte-identical (DER SHA-256) to this cert.
- `--card`: `sharingProhibited` must match the card's request (default true). Without `--card`, it must be true.
- passTypeIdentifier and teamIdentifier must equal the signer's UID and OU. No webServiceURL or authenticationToken.
- It prints value lengths only, never field values, unless you pass `--show-except key1,key2`.

### Exit codes
| code | meaning |
|---|---|
| 0 | RESULT OK: every check passed, including the trust chain |
| 1 | RESULT FAILED |
| 2 | usage error |
| 3 | not Apple-verified: RESULT OK-UNTRUSTED (`--no-chain`, chain not checked) or RESULT OK-TEST-UNPINNED (`--test-unpinned-chain`, Apple pins not enforced). Never treat this as OK. |

`finish.sh` exits 0 (READY, installed at `--out`), 1 (failed, nothing installed), 2 (usage error) or
4 (TEST BUILD with `--test-unpinned-chain`, left at the `.TEST-UNPINNED.pkpass` name, not Apple-verified).

## Privacy
`makepass.py` opens the private key exactly once, with `O_NOFOLLOW` and `O_NOCTTY`, checks that open file
(a regular file that group and others can't read), and hands it to `openssl` as `/dev/fd/N`. It is never
reopened by path, so swapping the file mid-run can't change which key signs. `finish.sh` never opens the key.
The tools refuse a key file that is a symlink, or whose path goes through a symlinked directory (for example a
`keys/` that is a symlink). Root-owned system links such as macOS `/tmp` and `/var` are allowed. The tools
never read, pipe or print the key's contents. Outputs are written mode 600. Temp files live in private
dirs next to the output, never in /tmp. `makepass.py` prints no field values.

## Tests
```
make test       # builds passes with a throwaway self-signed test CA chain; no network, no Apple account
make mutation   # re-introduces old bugs and checks the tests catch them
```

## License
MIT. See `LICENSE`.
