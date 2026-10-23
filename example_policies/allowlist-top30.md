# allowlist-top30.json

Distrusts every common root except these 30 (generated 2026-10-23):

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
| GlobalSign Root R46 | GlobalSign (RSA) | www.globalsign.com, newer GlobalSign chains |
| GlobalSign Root E46 | GlobalSign (ECDSA) | cnn.com, walmart.com |
| USERTrust RSA Certification Authority | Sectigo (RSA) | GitLab, ghcr.io, eBay, ZeroSSL |
| USERTrust ECC Certification Authority | Sectigo (ECDSA) | GitHub |
| Sectigo Public Server Authentication Root R46 | Sectigo (new RSA) | intel.com, skyhigh.cloud |
| AAA Certificate Services | Sectigo (legacy) | cross-sign path to USERTrust for old clients |
| Amazon Root CA 1 | Amazon Trust Services (RSA) | AWS (ACM) endpoints |
| Amazon Root CA 3 | Amazon Trust Services (ECDSA) | AWS ECDSA certificates |
| Go Daddy Root Certificate Authority - G2 | GoDaddy | older GoDaddy customers |
| GoDaddy TLS Root CA - R1 | GoDaddy | www.godaddy.com (served cross-signed by G2) |
| Starfield Root Certificate Authority - G2 | GoDaddy (Starfield) | Starfield customers |
| IdenTrust Commercial Root CA 1 | IdenTrust (HydrantID) | cisco.com, webex.com |
| Microsoft RSA Root Certificate Authority 2017 | Microsoft | Microsoft/Azure services |
| Microsoft ECC Root Certificate Authority 2017 | Microsoft | Microsoft/Azure services |
| SSL.com TLS RSA Root CA 2022 | SSL.com (RSA) | www.ssl.com, SSL.com customers |
| SSL.com TLS ECC Root CA 2022 | SSL.com (ECDSA) | registrar-servers.com (Namecheap) |
| SSL.com Root Certification Authority RSA | SSL.com (legacy RSA) | older SSL.com chains |
| SSL.com Root Certification Authority ECC | SSL.com (legacy ECDSA) | cloudflare-dns.com (1.1.1.1 DNS over HTTPS) |

The 238 entries are the union of five sets, minus the 30 roots above:

- the current Mozilla root set (curl's `cacert.pem`, 2026-10-20)
- the Chrome Root Store (`net/data/ssl/chrome_root_store/root_store.certs`)
- this host's NSS built-ins (`libnssckbi.so`, including email-only roots)
- Debian's `ca-certificates` 20250419
- Microsoft's root program (`authroot.stl` of 2026-08-25): the 234 roots
  enabled for server authentication, fetched by thumbprint from
  `ctldl.windowsupdate.com`. Windows downloads these on demand, and Edge
  ships them built in, so they must be blocked there even though no other
  store has them (82 are Microsoft-only).
  Microsoft's own code-signing and timestamping roots are not TLS-enabled and
  are not included.

Each entry uses `spki` matching. Its `comment` says which of the five sets it came from.

Checked with curl against the Tranco top 1000 domains (bare domain, then
`www.`), trusting only the 30 roots. 734 answered HTTPS with the normal system
store; 721 of those verified. The 13 failures, by the root they need:

- HARICA TLS RSA/ECC Root CA 2021: dzen.ru, okcdn.ru, vk.ru, vkuserphoto.ru,
  userapi.com, ok.ru, rustore.ru, vkontakte.ru, t2.ru
- DigiCert TLS RSA4096 Root G5: dnsmadeeasy.com
- Actalis TLS Server RSA Root CA 2025: huawei.com
- SECOM Security Communication RootCA2: yahoo.co.jp
- GlobalSign Root CA - R6: moe.video

Per-site results, anchor counts, and the allowed roots no site anchored at
are in `allowlist-top30-results.txt`.

Known gaps:

- Customers of HARICA, Entrust, Certum, Buypass, QuoVadis, Actalis, SECOM,
  GlobalSign's legacy ECC and R6 roots, SSL.com's EV roots, DigiCert's
  G5 roots, Google's GTS R2/R3, Sectigo's E46 and legacy COMODO RSA roots, government and national CAs, and private enterprise CAs will break.
- Entries match by key (`spki`), so blocking a root also blocks every
  cross-signed copy of it. A site whose chain passes through a blocked root's
  cross-sign (even one issued by an allowed root) breaks. This is why
  `GoDaddy TLS Root CA - R1` is allowed: `www.godaddy.com` serves it as an
  intermediate under Go Daddy G2. Legacy `COMODO RSA Certification Authority`
  chains are blocked.
- EC-ACC (Catalan government, Microsoft-only) is not blocked: its negative
  serial number is rejected by Go's X.509 parser, so it can't be a policy entry.
- On Windows the `system` backend uses the `Disallowed` store, which distrusts
  a root for every purpose, not only TLS. Code signed or timestamped under any
  blocked root will show as untrusted.

Check it before enforcing:

    distrust list --policy example_policies/allowlist-top30.json

Enforce in chrome:

    sudo distrust apply --policy example_policies/allowlist-top30.json --backends chromium

Undo:

    sudo distrust apply --policy example_policies/empty-policy.json --backends chromium
