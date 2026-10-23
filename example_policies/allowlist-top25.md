# allowlist-top25.json

Distrusts every common root except these 25 (generated 2026-10-23):

| Root | Operator | Typical users |
|---|---|---|
| ISRG Root X1 | Let's Encrypt (RSA) | X, Debian mirrors, most small sites |
| ISRG Root X2 | Let's Encrypt (ECDSA) | Wikipedia |
| DigiCert Global Root G2 | DigiCert (RSA) | Microsoft/Azure, Amazon.com, Meta, PayPal, Yahoo |
| DigiCert Global Root G3 | DigiCert (ECDSA) | Apple, iCloud, Netflix |
| DigiCert Global Root CA | DigiCert (legacy RSA) | older DigiCert chains still in service |
| DigiCert High Assurance EV Root CA | DigiCert (legacy EV) | older EV and DigiCert-issued chains |
| DigiCert Assured ID Root CA | DigiCert | code signing and timestamping, some TLS |
| DigiCert Trusted Root G4 | DigiCert | code signing and timestamping (Windows) |
| GTS Root R1 | Google (RSA) | Google RSA chains, Google Cloud customers |
| GTS Root R4 | Google (ECDSA) | Google, YouTube, Cloudflare |
| GlobalSign Root CA | GlobalSign (R1) | cross-signs GTS R1/R4, older GlobalSign chains |
| GlobalSign Root CA - R3 | GlobalSign | PyPI, BBC |
| GlobalSign Root R46 | GlobalSign | www.globalsign.com, newer GlobalSign chains |
| USERTrust RSA Certification Authority | Sectigo (RSA) | GitLab, ghcr.io, eBay, ZeroSSL |
| USERTrust ECC Certification Authority | Sectigo (ECDSA) | GitHub |
| COMODO RSA Certification Authority | Sectigo (legacy RSA) | older Sectigo/Comodo chains |
| AAA Certificate Services | Sectigo (legacy) | cross-sign path to USERTrust for old clients |
| Amazon Root CA 1 | Amazon Trust Services (RSA) | AWS (ACM) endpoints |
| Amazon Root CA 3 | Amazon Trust Services (ECDSA) | AWS ECDSA certificates |
| Starfield Services Root Certificate Authority - G2 | Amazon Trust Services | cross-sign path to Amazon roots for old clients |
| Go Daddy Root Certificate Authority - G2 | GoDaddy | www.godaddy.com, GoDaddy customers |
| Starfield Root Certificate Authority - G2 | GoDaddy (Starfield) | Starfield customers |
| Microsoft RSA Root Certificate Authority 2017 | Microsoft | Microsoft/Azure services |
| Microsoft ECC Root Certificate Authority 2017 | Microsoft | Microsoft/Azure services |
| SSL.com TLS RSA Root CA 2022 | SSL.com | www.ssl.com, SSL.com customers |

The 243 entries are the union of five sets, minus the 25 roots above:

- the current Mozilla root set (curl's `cacert.pem`, 2026-10-20)
- the Chrome Root Store (`net/data/ssl/chrome_root_store/root_store.certs`)
- this host's NSS built-ins (`libnssckbi.so`, including email-only roots)
- Debian's `ca-certificates` 20250419
- Microsoft's root program (`authroot.stl` of 2026-08-25): the 234 roots
  enabled for server authentication, fetched by thumbprint from
  `ctldl.windowsupdate.com`. Windows downloads these on demand, and Edge
  ships them built in, so they must be blocked there even though no other
  store has them (82 are Microsoft-only, e.g. GoDaddy TLS Root CA - R1).
  Microsoft's own code-signing and timestamping roots are not TLS-enabled and
  are not included.

Each entry uses `spki` matching. Its `comment` says which of the five sets it came from.

Checked by connecting to 58 popular sites with curl, trusting only the 25
roots: 57 verified. `www.harica.gr` failed because HARICA is blocked. The
top-10 list also failed `www.globalsign.com`, `www.godaddy.com` and `www.ssl.com`.

Known gaps:

- Customers of HARICA, Entrust, Certum, Buypass, QuoVadis, the GlobalSign E46
  and ECC roots, SSL.com's ECC and legacy roots, Google's GTS R2/R3,
  government and national CAs, and private enterprise CAs will break.
- `GoDaddy TLS Root CA - R1` (Microsoft-only) is blocked. On Windows,
  `www.godaddy.com` must therefore build its path to the allowed Go Daddy G2;
  check it with a browser before relying on it.
- EC-ACC (Catalan government, Microsoft-only) is not blocked: its negative
  serial number is rejected by Go's X.509 parser, so it can't be a policy entry.
- On Windows the `system` backend uses the `Disallowed` store, which distrusts
  a root for every purpose, not only TLS. Code signed or timestamped under any
  blocked root will show as untrusted.

Check it before enforcing:

    distrust list --policy example_policies/allowlist-top25.json

Enforce in chrome:

    sudo distrust apply --policy example_policies/allowlist-top25.json --backends chromium

Undo:

    sudo distrust apply --policy example_policies/empty-policy.json --backends chromium
