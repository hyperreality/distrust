# allowlist-top10.json

Distrusts every common root except these ten (generated 2026-10-23):

| Root | Operator | Typical users |
|---|---|---|
| ISRG Root X1 | Let's Encrypt (RSA) | X, Debian mirrors, most small sites |
| ISRG Root X2 | Let's Encrypt (ECDSA) | Wikipedia |
| DigiCert Global Root G2 | DigiCert (RSA) | Microsoft/Azure, Amazon.com, Meta, PayPal, Yahoo |
| DigiCert Global Root G3 | DigiCert (ECDSA) | Apple, iCloud, Netflix |
| GTS Root R1 | Google (RSA) | Google RSA chains, Google Cloud customers |
| GTS Root R4 | Google (ECDSA) | Google, YouTube, Cloudflare |
| USERTrust RSA Certification Authority | Sectigo (RSA) | GitLab, ghcr.io, eBay, ZeroSSL |
| USERTrust ECC Certification Authority | Sectigo (ECDSA) | GitHub |
| Amazon Root CA 1 | Amazon Trust Services | AWS (ACM) endpoints |
| GlobalSign Root CA - R3 | GlobalSign | PyPI, BBC |

The 258 entries are the union of five sets, minus the ten roots above:

- the current Mozilla root set (curl's `cacert.pem`, 2026-10-20)
- the Chrome Root Store (`net/data/ssl/chrome_root_store/root_store.certs`)
- this host's NSS built-ins (`libnssckbi.so`, including email-only roots)
- Debian's `ca-certificates` 20250419
- Microsoft's root program (`authroot.stl` of 2026-08-25): the 234 roots
  enabled for server authentication, fetched by thumbprint from
  `ctldl.windowsupdate.com`. Windows downloads these on demand, and Edge
  ships them built in, so they must be blocked there even though no other
  store has them (82 are Microsoft-only, e.g. GoDaddy TLS Root CA - R1, which
  `www.godaddy.com` anchors at on Windows instead of the blocked Go Daddy G2).
  Microsoft's own code-signing and timestamping roots are not TLS-enabled and
  are not included.

Each entry uses `spki` matching. Its `comment` says which of the five sets it came from.

Checked by connecting to 51 popular sites while trusting only the ten roots: 50 verified. `www.globalsign.com` failed because it now anchors at GlobalSign Root R46, which is blocked.

Known gaps:

- GoDaddy and Starfield customers will break.
- So will GlobalSign R46/E46 customers, Entrust/SSL.com/HARICA customers, government and national CAs, and private enterprise CAs.
- EC-ACC (Catalan government, Microsoft-only) is not blocked: its negative
  serial number is rejected by Go's X.509 parser, so it can't be a policy entry.
- On Windows the `system` backend uses the `Disallowed` store, which distrusts
  a root for every purpose, not only TLS. Code signed or timestamped under a
  blocked root (e.g. DigiCert Trusted Root G4, DigiCert Assured ID Root CA)
  will show as untrusted, and Microsoft services that chain to the blocked
  Microsoft RSA/ECC Root Certificate Authority 2017 may fail.
- Blocking `AAA Certificate Services` and `Starfield Services Root CA - G2` only removes the legacy cross-sign paths to USERTrust and Amazon. Modern verifiers stop at the trusted root.

Check it before enforcing:

    distrust list --policy example_policies/allowlist-top10.json

Enforce in chrome:

    sudo distrust apply --policy example_policies/allowlist-top10.json --backends chromium

Undo:

    sudo distrust apply --policy example_policies/empty-policy.json --backends chromium
