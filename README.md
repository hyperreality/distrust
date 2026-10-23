# distrust

Why does my system trust over 150 root signing authorities, most of which I will never use? The recent [eMudhra CA compromise](https://emudhra.we-have-a-problem.com/) highlighted the flaws with this model. 

**distrust** is a tool for blocking CA certificates across every trust store on a host, not only the OS bundle. Confusingly, browsers (NSS, Chrome Root Store), OpenSSL/GnuTLS consumers (curl, wget, Python, Go), Java, and the standalone PEM bundles that apps ship (certifi, conda, botocore) each keep their own copy of the roots. Removing a CA from one of them leaves it trusted in many other places.

**distrust** ships with example policies that block all CAs except the top 10. Try it and see what breaks!

There did not appear to be existing tools to do this, probably because there is so much variance across operating system platforms, distros, and programming languages. **distrust** is therefore shamelessly vibe-coded to deal with all these edge cases.

Tested on Debian Linux and Windows. Alpha release, expect breakage!

## Usage

(More detailed examples below)

```
distrust block <cert.pem | --sha256 X | --from-url host:443> [--backends nss,system] [--dry-run]
distrust unblock <id>
distrust list                      # policy entries + per-backend state
distrust status <id|cert.pem>      # matrix: backend × trusted/distrusted/absent
distrust apply [--policy file]     # converge to policy (used by timer)
distrust scan [--paths /opt,/usr]  # find PEM bundles / cacerts / NSS DBs containing the cert
distrust backends                  # what was detected on this host
distrust verify [id|cert.pem]      # real x509 chain check per store to confirm
               [--probe host:443]  # replay host's live chain to the real browsers
```

Global flags work in any position: `--policy FILE`, `--state-dir DIR`, `--json`, `-v`.

## Build & install

### Linux

```sh
go build -o distrust ./cmd/distrust          # stdlib only, no dependencies
sudo contrib/install.sh                      # binary + systemd timer/path units + apt/pacman hook
```

### macOS

```sh
GOOS=darwin go build ./cmd/distrust          # cross-compiles for macOS
```

### Windows

```sh
GOOS=windows go build -o distrust.exe ./cmd/distrust          # cross-compiles for Windows
```

Runtime helpers (used only if present): `certutil`, `vfychain` and `modutil` from NSS (`apt install libnss3-tools`, `dnf install nss-tools`, `brew install nss`), `keytool` from a JDK, and `/usr/bin/openssl` for verification.

## Examples

```sh
# Block the root behind a site (servers rarely send the root; it is found in local stores)
sudo distrust block --from-url evil.example:443

# Block a CA you have as a file, browsers only
sudo distrust block ./corp-mitm-ca.pem --backends nss

# Block a CA already in a store, by cert or SPKI fingerprint
sudo distrust block --sha256 03:76:AB:1D:...:5F:A7

# Look before blocking, then confirm afterwards with real chain checks
distrust status ./ca.pem -v
sudo distrust verify 0376ab1d54c5     # exit code 3 if any targeted store still trusts it

# Find app-private bundles and keystores, bring them under management
sudo distrust scan --paths /opt,/home,/usr/lib/python3
sudo distrust scan --adopt && sudo distrust apply
```

## Design

```
            ┌───────────── policy.json (desired) ─────────────┐
 block ───► │ entries: id, sha256, spki, PEM(s), backends[]   │ ◄── edited by hand / CM tools
 unblock    │ bundles[], keystores[], nss_dbs[] (adopted)     │
            └────────────────────────┬────────────────────────┘
                                     │  engine.Apply()  (block / timer / apt hook / path unit)
                                     ▼
       ┌─────────┬─────────────┬─────────────┬────────────┐
       │  nss    │  system     │  java       │  bundle    │   backend.Backend interface
       └────┬────┴──────┬──────┴──────┬──────┴─────┬──────┘
            ▼           ▼             ▼            ▼
      state.json (what was actually changed, so unblock restores it exactly)
```

* **Policy** (`/etc/distrust/policy.json` as root,
  `~/.config/distrust/policy.json` otherwise) is the desired state. Each
  entry stores the certificate PEM itself, because NSS, Keychain and Windows
  can only distrust a cert you hand them, and new profiles created later need
  it too.
* **State** (`/var/lib/distrust/state.json`) records what each backend
  changed: the trust flags a cert had in an NSS DB before we changed them,
  the `ca-certificates.conf` lines we negated, files moved to quarantine,
  keystore aliases deleted (with their PEM), and bundle blocks cut out
  (byte-exact). Unblocking reverts exactly that and nothing else. State also
  keeps a copy of each entry so a record can still be undone after its entry
  has been deleted from the policy.
* **Engine** reconciles: block every entry on every targeted backend that is
  available and writable, and unblock state records whose entry is gone or no
  longer targets that backend. Every backend operation is idempotent, so
  `apply` is safe to run at any time. Run it from the timer, from the
  dpkg/pacman hook, or when the policy or system bundle changes (the path
  unit). That is how new Firefox profiles, new JDKs and
  `ca-certificates`/`certifi` upgrades get handled.
* **Matching**: `--match spki` (the default) matches certificates with the
  same subject and public key. A re-issued or cross-signed copy of the CA
  is therefore caught as well. Copies found in local stores at block time
  are stored as variants. `--match cert` matches only the exact cert.

### Backends

| name     | platform | stores | how distrust is expressed |
|----------|----------|--------|---------------------------|
| `nss`    | all      | Firefox/Thunderbird/LibreWolf profiles (incl. snap & flatpak), `~/.pki/nssdb` (Chromium/Chrome on Linux), `/etc/pki/nssdb`, extra `nss_dbs` | Import with trust `p,p,p` via `certutil`, or change an existing cert's flags (and record the old ones). This overrides the built-in roots and can also distrust **intermediates**. |
| `system` | Linux    | Debian/Ubuntu/Alpine `ca-certificates` | Packaged certs: `!path` in `/etc/ca-certificates.conf`. Admin-added certs: moved to quarantine. Then `update-ca-certificates` regenerates the bundle and hash dir and runs the Java hook. |
|          | Linux    | Fedora/RHEL, Arch, openSUSE (p11-kit) | PEM written to the p11-kit blocklist dir, then `update-ca-trust extract`. |
|          | macOS    | admin trust settings | `security add-trusted-cert -d -r deny` (experimental, not yet tested on a Mac) |
|          | Windows  | `LocalMachine\Disallowed` | `certutil -addstore Disallowed`. This also beats automatic root updates (experimental, not yet tested on Windows). |
| `chromium` | Linux, Windows | Chrome, Chromium (Debian/Fedora/Arch and Ubuntu's `chromium-browser`), Edge, Brave, Vivaldi, Opera | Writes the `CADistrustedCertificates` enterprise policy (Chromium 132+) to `<policy dir>/managed/zz-distrust.json` on Linux, or to `HKLM\SOFTWARE\Policies\<vendor>` on Windows (experimental). Matches by SPKI and overrides the Chrome Root Store. See [Chromium-based browsers](#chromium-based-browsers). |
| `java`   | all      | JDK/JRE `cacerts` (deduplicated through symlinks), extra `keystores` | JKS has no distrust, so matching `trustedCertEntry` aliases are deleted with `keytool` and re-imported on unblock. JKS is read natively; PKCS#12 is read through keytool. |
| `bundle` | all      | PEM bundles in policy `bundles` (adopted via `scan --adopt`) | The block, including its `# comment` header, is cut out and stored for restore. |

`status` reads each store directly (fast). `verify` checks each store the
way its consumers would:

* NSS: `vfychain -u 3` on a temp copy of each DB with the built-in roots
  module loaded. `SEC_ERROR_UNTRUSTED_CERT` means explicitly distrusted.
* system: `openssl verify` with `-CAfile` and with `-CApath`, plus Go
  `crypto/x509`.
* java and bundle: Go `crypto/x509` with the store's anchors.
* macOS and Windows: Go's verifier, which calls the platform verifier.

### Adding a backend

Implement `backend.Backend` (`Detect`, `Status`, `Block`, `Unblock`,
`Verify`), and optionally `CertLister` so `--sha256` and variant lookups can
search it. Register it in `init()` and import it from
`internal/backend/all` (in a per-OS file if it is platform-specific).
Persist undo data with `env.State.Put`, and keep `Block` idempotent. Likely
next ones: macOS configuration profiles for Chromium/Firefox policies, Node
(`NODE_EXTRA_CA_CERTS` can't remove roots, so the best available is a warning
or a wrapper), container images, and `.NET` on Linux (which uses the system
store already).

## Chromium-based browsers

Summary of the investigation behind the `chromium` backend. Tested on Debian 13
with Chrome 156, Chromium 156, Edge 156, Brave 1.98 (Chromium 156), Vivaldi 8.2
and Opera 138. All six were tested with the replay probe described below,
which observed rejection after distrusting WE2. Brave and Vivaldi were also
tested in a real window, where the page showed the "Privacy error"
interstitial.

**How Chromium decides trust on Linux.** It uses its own verifier and the
compiled-in Chrome Root Store, not the system bundle. So the `system`
backend doesn't affect it, and neither do `/etc/ssl/certs` edits or p11-kit.
Three trust sources are combined, and a distrust from any of them wins
(`bssl::TrustStoreCollection`):

| source | used when | how it matches | finding |
|---|---|---|---|
| `CADistrustedCertificates` policy | always (Chromium 132+, all desktop OSes, ChromeOS, Android) | **SPKI**: every certificate with that key | Works in all six browsers. Overrides the Chrome Root Store, NSS trust and `CACertificates`. Applies to all users and profiles. A running browser reloads it in about 10–15 s, no restart needed. |
| NSS `~/.pki/nssdb` (the `nss` backend) | `CAPlatformIntegrationEnabled` is true (the default) | **exact certificate DER** | Honored (`p,p,p` is reported as "Distrusted by trust store"), but **bypassed** whenever the path builder finds another certificate with the same key. Observed live: the served WE2 intermediate was distrusted, Chrome switched to a cross-signed WE2 that chains to GlobalSign, and accepted. Per user only. |
| Chrome Root Store | always | built in | Can't be edited, only overridden. |

**Pitfalls the backend handles:**

* **Multiple policy files don't merge.** Chromium reads *every* file in
  `managed/` in lexicographic order, and the last file that sets a key wins
  (`ConfigDirPolicyLoader`). `distrust` owns `zz-distrust.json`, carries over
  values from any earlier file that sets `CADistrustedCertificates`, warns if a
  later file overrides it, and removes its file once nothing is left to
  distrust, so the admin's value takes effect again. Staging writes in
  `managed/` itself would be unsafe, because Chromium reads dotfiles too, so
  temp files go in the parent directory.
* **Policy directories differ by vendor.** These were read from each shipped
  binary: `/etc/opt/chrome`, `/etc/chromium`, `/etc/chromium-browser`
  (Ubuntu snap), `/etc/opt/edge`, `/etc/brave`, `/etc/vivaldi` (not under
  `/etc/opt`!), `/etc/opt/opera`. Each has a `policies/managed` subdirectory.
  `recommended/` also works for this policy, and file ownership and mode are
  not checked.
* **Blocking "the root" may not block anything.** A distrust only matters if
  the distrusted key is on the path the browser builds. Blocking GTS Root R4
  left google.com trusted in every browser: five anchored at WE2, and Edge at
  GlobalSign ECC Root CA R4. Only distrusting WE2 rejected it everywhere.
  `status` can't see this, but `verify --probe` can.

**How `verify` works for browsers.** For each installed browser, `distrust`
starts the real binary with a throwaway profile. It uses a private Xvfb if
available, because Brave and Vivaldi don't navigate in headless mode. It then
reads the browser's own net-log:

* `CERT_VERIFY_PROC_ADDITIONAL_CERT` events prove the SPKI reached the
  certificate verifier, not just `chrome://policy`.
* With `--probe host:443`, the host's real chain is served from 127.0.0.1
  using a random key of the leaf's type, and the browser is pointed there with
  `--host-resolver-rules`. BoringSSL verifies the chain *before* checking
  `CertificateVerify`, so the browser's verdict and the path it built
  (including the anchor) are logged with no real traffic and no private key.
  The result is either "rejected (Distrusted by trust store at CN=WE2)" or
  "ACCEPTED via anchor X; this CA's key is not on that path".

As root, the browsers run as the invoking `sudo` user, so the sandbox stays on.
`DISTRUST_BROWSERS="edge=/path/msedge,..."` points at non-standard installs.

**Not covered:** on macOS, Chromium honors policy only from managed
preferences, which come from a configuration profile/MDM, so it is listed as
unsupported for now. On Windows, a Group Policy refresh rewrites the policy
key if a GPO also sets `CADistrustedCertificates`. Browsers older than 132
ignore the policy, and `backends`/`status` flag them as `unsupported`.

## Limitations

* **Flat PEM stores (OpenSSL/GnuTLS bundles, Java, certifi) can only drop
  roots.** An intermediate that chains to a trusted root cannot be distrusted
  there; `status` shows `unsupported`. Block the issuing root, or rely on NSS
  for browsers.
* Programs with **compiled-in roots** (Node.js's default store, some
  Rust/Electron apps) can't be changed from outside. Use `scan` to find the
  bundles they do ship.
* Running browsers keep trust decisions in memory; **restart** them after
  blocking. `backends` marks profiles that are in use.
* On Debian, `/etc/ssl/certs/java/cacerts` is regenerated by
  ca-certificates-java from the system store. Running both the `system` and
  `java` backends keeps them consistent.
* Without root, only the current user's NSS DBs and writable files are
  changed; system stores show as `read-only` and are skipped.
* `DISTRUST_HOMES` (an OS path list) limits which home directories are
  searched, e.g. one user, or a sandbox for testing.
  `DISTRUST_JAVA_STOREPASS` overrides `changeit`.

## Exit codes

`0` success, `1` error, `2` usage, `3` (`status`/`verify`) a targeted store
still trusts a blocked CA, which makes it usable from monitoring.
