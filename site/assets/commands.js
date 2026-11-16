// Generated from the cogs so the site cannot drift from the bot.
// Rebuild with: python tools/build_catalog.py
window.COMMAND_DATA = {
 "categories": [
  {
   "key": "network",
   "label": "Network",
   "count": 27
  },
  {
   "key": "domain",
   "label": "Domain",
   "count": 26
  },
  {
   "key": "web",
   "label": "Web",
   "count": 30
  },
  {
   "key": "identity",
   "label": "Identity",
   "count": 16
  },
  {
   "key": "social",
   "label": "Social",
   "count": 17
  },
  {
   "key": "discord",
   "label": "Discord",
   "count": 23
  },
  {
   "key": "vuln",
   "label": "Vulnerability",
   "count": 12
  },
  {
   "key": "crypto",
   "label": "Crypto",
   "count": 7
  },
  {
   "key": "craft",
   "label": "Craft",
   "count": 40
  },
  {
   "key": "toolkit",
   "label": "Toolkit",
   "count": 130
  },
  {
   "key": "generator",
   "label": "Generator",
   "count": 29
  },
  {
   "key": "system",
   "label": "System",
   "count": 23
  }
 ],
 "commands": [
  {
   "name": "asn",
   "category": "network",
   "brief": "Autonomous system summary: holder, registry, website, prefix and peer counts.",
   "usage": "<asn>",
   "aliases": [
    "whois-as"
   ],
   "sources": [
    "RIPEstat"
   ]
  },
  {
   "name": "asnprefixes",
   "category": "network",
   "brief": "Every IPv4 and IPv6 prefix announced by an autonomous system.",
   "usage": "<asn>",
   "aliases": [
    "prefixes"
   ],
   "sources": [
    "RIPEstat"
   ]
  },
  {
   "name": "bgppeers",
   "category": "network",
   "brief": "BGP peer relationships for an autonomous system.",
   "usage": "<asn>",
   "aliases": [
    "peers"
   ],
   "sources": [
    "RIPEstat"
   ]
  },
  {
   "name": "cdn",
   "category": "network",
   "brief": "CDN and WAF fingerprinting from CNAME chains, headers and cookies.",
   "usage": "<host>",
   "aliases": [
    "edge"
   ],
   "sources": [
    "Cloudflare DoH",
    "direct HTTP"
   ]
  },
  {
   "name": "ciphersuite",
   "category": "network",
   "brief": "Decompose a TLS cipher suite name.",
   "usage": "ciphersuite <suite>",
   "aliases": [
    "tlsname"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "dnstype",
   "category": "network",
   "brief": "Explain a DNS record type.",
   "usage": "dnstype <type>",
   "aliases": [
    "rrttype"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "geo",
   "category": "network",
   "brief": "Geolocation-first view of an address with map coordinates and locale detail.",
   "usage": "<ipv4|ipv6>",
   "aliases": [
    "geolocate",
    "loc"
   ],
   "sources": [
    "ipwho.is"
   ]
  },
  {
   "name": "headers",
   "category": "network",
   "brief": "Response headers, redirect chain and a security-header coverage count.",
   "usage": "<url|host>",
   "aliases": [
    "responseheaders"
   ],
   "sources": [
    "direct HTTP"
   ]
  },
  {
   "name": "httpstatus",
   "category": "network",
   "brief": "Status code, redirect hops, protocol and transfer timing for a URL.",
   "usage": "<url>",
   "aliases": [
    "http"
   ],
   "sources": [
    "direct HTTP"
   ]
  },
  {
   "name": "icmpcode",
   "category": "network",
   "brief": "Explain an ICMP type and code.",
   "usage": "icmpcode <type|code>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "ip",
   "category": "network",
   "brief": "Full address report: geography, owning network, security flags and reverse DNS.",
   "usage": "<ipv4|ipv6>",
   "aliases": [
    "ipinfo"
   ],
   "sources": [
    "ipwho.is",
    "Cloudflare DoH"
   ]
  },
  {
   "name": "ipv6",
   "category": "network",
   "brief": "IPv6 structural analysis: scope, embedded IPv4, reverse nibble zone and RFC 5952 form.",
   "usage": "<ipv6>",
   "aliases": [
    "v6"
   ],
   "sources": [
    "local computation",
    "ipwho.is"
   ]
  },
  {
   "name": "ipv6type",
   "category": "network",
   "brief": "Classify an IPv6 address (ULA, link-local, 6to4, Teredo).",
   "usage": "ipv6type <ipv6>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "mac",
   "category": "network",
   "brief": "MAC address anatomy and IEEE OUI vendor resolution.",
   "usage": "<mac>",
   "aliases": [
    "oui"
   ],
   "sources": [
    "api.macvendors.com"
   ]
  },
  {
   "name": "myip",
   "category": "network",
   "brief": "Egress address of this bot instance, fully enriched.",
   "usage": "myip",
   "aliases": [
    "egress"
   ],
   "sources": [
    "api.ipify.org",
    "ipwho.is"
   ]
  },
  {
   "name": "netblock",
   "category": "network",
   "brief": "Network block arithmetic for an address or CIDR: range, hosts, masks and reverse zone.",
   "usage": "<cidr|ip>",
   "aliases": [
    "cidr",
    "subnet"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "portcheck",
   "category": "network",
   "brief": "TCP reachability, handshake latency and service banner for a single port.",
   "usage": "<host> [port]",
   "aliases": [
    "port"
   ],
   "sources": [
    "direct TCP"
   ]
  },
  {
   "name": "portrange",
   "category": "network",
   "brief": "Expand a port list or range.",
   "usage": "portrange <80,443,8000-8100>",
   "aliases": [
    "ports"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "rangeexpand",
   "category": "network",
   "brief": "Expand an IPv4 range into addresses.",
   "usage": "rangeexpand <first|last>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "rbl",
   "category": "network",
   "brief": "Check an address against fourteen DNS blocklists.",
   "usage": "<ip>",
   "aliases": [
    "blacklist",
    "dnsbl"
   ],
   "sources": [
    "14 DNSBL zones over DoH"
   ]
  },
  {
   "name": "rdns",
   "category": "network",
   "brief": "Reverse DNS with forward-confirmation of the pointer target.",
   "usage": "<ip>",
   "aliases": [
    "ptr",
    "reversedns"
   ],
   "sources": [
    "Cloudflare DoH"
   ]
  },
  {
   "name": "subnetinfo",
   "category": "network",
   "brief": "Full breakdown of a CIDR block.",
   "usage": "subnetinfo <cidr>",
   "aliases": [
    "subnetcalc"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "supernet",
   "category": "network",
   "brief": "Summarise a block into a parent prefix.",
   "usage": "supernet <cidr|prefix>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "tcpflags",
   "category": "network",
   "brief": "Decode a TCP flag byte or flag names.",
   "usage": "tcpflags <0x12|SYN,ACK>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "tls",
   "category": "network",
   "brief": "TLS certificate and protocol inspection: issuer, SANs, expiry, ciphers, fingerprints.",
   "usage": "<host> [port]",
   "aliases": [
    "cert",
    "ssl"
   ],
   "sources": [
    "direct TLS handshake"
   ]
  },
  {
   "name": "vpncheck",
   "category": "network",
   "brief": "VPN, proxy, Tor and datacenter verdict for an address.",
   "usage": "<ipv4|ipv6>",
   "aliases": [
    "vpn",
    "ipvpn",
    "anonymity"
   ],
   "sources": [
    "ipquery.io",
    "ip-api.com"
   ]
  },
  {
   "name": "whoisip",
   "category": "network",
   "brief": "RDAP registration record for an IP: network block, holder, abuse contacts.",
   "usage": "<ip>",
   "aliases": [
    "ipwhois",
    "rdapip"
   ],
   "sources": [
    "rdap.org"
   ]
  },
  {
   "name": "a",
   "category": "domain",
   "brief": "IPv4 records with TTLs and reverse DNS for each address.",
   "usage": "<domain>",
   "aliases": [
    "arecord"
   ],
   "sources": [
    "Cloudflare DoH"
   ]
  },
  {
   "name": "aaaa",
   "category": "domain",
   "brief": "IPv6 records for a domain with TTL detail.",
   "usage": "<domain>",
   "aliases": [
    "aaaarecord"
   ],
   "sources": [
    "Cloudflare DoH"
   ]
  },
  {
   "name": "authresults",
   "category": "domain",
   "brief": "Parse an Authentication-Results header.",
   "usage": "authresults <header value>",
   "aliases": [
    "mailauth"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "caa",
   "category": "domain",
   "brief": "Certificate Authority Authorization: which CAs may issue for this name.",
   "usage": "<domain>",
   "aliases": [
    "caarecord"
   ],
   "sources": [
    "Cloudflare DoH"
   ]
  },
  {
   "name": "cname",
   "category": "domain",
   "brief": "CNAME chain with the final address set and CDN detection.",
   "usage": "<domain>",
   "aliases": [
    "alias"
   ],
   "sources": [
    "Cloudflare DoH"
   ]
  },
  {
   "name": "crtsh",
   "category": "domain",
   "brief": "Certificate Transparency search: issuers, validity window and covered names.",
   "usage": "<domain>",
   "aliases": [
    "ct",
    "certs"
   ],
   "sources": [
    "crt.sh"
   ]
  },
  {
   "name": "dkim",
   "category": "domain",
   "brief": "Hunt for DKIM selectors and estimate the signing key size.",
   "usage": "<domain> [selector]",
   "aliases": [
    "dkimkey"
   ],
   "sources": [
    "Cloudflare DoH"
   ]
  },
  {
   "name": "dmarc",
   "category": "domain",
   "brief": "DMARC policy analysis: enforcement, alignment, reporting addresses and coverage.",
   "usage": "<domain>",
   "aliases": [
    "dmarcpolicy"
   ],
   "sources": [
    "Cloudflare DoH"
   ]
  },
  {
   "name": "dns",
   "category": "domain",
   "brief": "Complete DNS snapshot: A, AAAA, MX, NS, TXT, CNAME, CAA and SOA in one table.",
   "usage": "<domain>",
   "aliases": [
    "dnsall",
    "records"
   ],
   "sources": [
    "Cloudflare DoH"
   ]
  },
  {
   "name": "dnssec",
   "category": "domain",
   "brief": "DNSSEC chain: DS at the parent and DNSKEY at the zone, with algorithm detail.",
   "usage": "<domain>",
   "aliases": [
    "ds"
   ],
   "sources": [
    "Cloudflare DoH"
   ]
  },
  {
   "name": "domainage",
   "category": "domain",
   "brief": "Domain age, expiry runway and registrar from the registration record.",
   "usage": "<domain>",
   "aliases": [
    "age",
    "expiry"
   ],
   "sources": [
    "port-43 WHOIS"
   ]
  },
  {
   "name": "emailposture",
   "category": "domain",
   "brief": "End-to-end email authentication posture score across SPF, DMARC, DKIM, DNSSEC and MTA-STS.",
   "usage": "<domain>",
   "aliases": [
    "mailposture",
    "emailauth"
   ],
   "sources": [
    "Cloudflare DoH",
    "direct HTTPS"
   ]
  },
  {
   "name": "idnlabels",
   "category": "domain",
   "brief": "Break a domain into ASCII and Unicode labels.",
   "usage": "idnlabels <domain>",
   "aliases": [
    "idncheck"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "mx",
   "category": "domain",
   "brief": "Mail exchangers, priorities and the hosting provider behind them.",
   "usage": "<domain>",
   "aliases": [
    "mail",
    "mxrecords"
   ],
   "sources": [
    "Cloudflare DoH"
   ]
  },
  {
   "name": "ns",
   "category": "domain",
   "brief": "Authoritative nameservers, their providers and resolved glue addresses.",
   "usage": "<domain>",
   "aliases": [
    "nameservers"
   ],
   "sources": [
    "Cloudflare DoH"
   ]
  },
  {
   "name": "propagation",
   "category": "domain",
   "brief": "Compare one record across four independent public resolvers.",
   "usage": "<domain> [type]",
   "aliases": [
    "prop"
   ],
   "sources": [
    "Cloudflare",
    "Google",
    "Quad9",
    "AdGuard"
   ]
  },
  {
   "name": "punycode",
   "category": "domain",
   "brief": "IDN / homograph analysis: punycode form, scripts and confusable characters.",
   "usage": "<domain>",
   "aliases": [
    "idn",
    "homograph"
   ],
   "sources": [
    "local Unicode analysis"
   ]
  },
  {
   "name": "rdap",
   "category": "domain",
   "brief": "Structured RDAP registration record with entities and events.",
   "usage": "<domain>",
   "aliases": [
    "registration"
   ],
   "sources": [
    "rdap.org"
   ]
  },
  {
   "name": "received",
   "category": "domain",
   "brief": "Parse a Received header chain.",
   "usage": "received <headers>",
   "aliases": [
    "mailhops"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "soa",
   "category": "domain",
   "brief": "Start of authority: primary server, serial and refresh/retry/expire timers.",
   "usage": "<domain>",
   "aliases": [
    "authority"
   ],
   "sources": [
    "Cloudflare DoH"
   ]
  },
  {
   "name": "spf",
   "category": "domain",
   "brief": "Parse and grade an SPF policy, including the 10-lookup budget.",
   "usage": "<domain>",
   "aliases": [
    "senderpolicy"
   ],
   "sources": [
    "Cloudflare DoH"
   ]
  },
  {
   "name": "srv",
   "category": "domain",
   "brief": "SRV records: service, protocol, priority, weight and target host.",
   "usage": "<_service._proto.domain>",
   "aliases": [
    "srvrecord"
   ],
   "sources": [
    "Cloudflare DoH"
   ]
  },
  {
   "name": "subdomains",
   "category": "domain",
   "brief": "Passive subdomain enumeration from Certificate Transparency, paginated.",
   "usage": "<domain>",
   "aliases": [
    "subs",
    "enum"
   ],
   "sources": [
    "crt.sh"
   ]
  },
  {
   "name": "tldinfo",
   "category": "domain",
   "brief": "TLD facts: IANA registration, class, root nameservers.",
   "usage": "<domain|tld>",
   "aliases": [
    "tld"
   ],
   "sources": [
    "data.iana.org",
    "Cloudflare DoH"
   ]
  },
  {
   "name": "txt",
   "category": "domain",
   "brief": "Every TXT record, classified by purpose (SPF, verification, policy).",
   "usage": "<domain>",
   "aliases": [
    "txtrecords"
   ],
   "sources": [
    "Cloudflare DoH"
   ]
  },
  {
   "name": "whois",
   "category": "domain",
   "brief": "Raw WHOIS with parsed registrar, dates, status flags and nameservers.",
   "usage": "<domain>",
   "aliases": [
    "whoisdomain"
   ],
   "sources": [
    "port-43 WHOIS via IANA referral"
   ]
  },
  {
   "name": "confusable",
   "category": "web",
   "brief": "Detect mixed-script labels in a domain.",
   "usage": "confusable <domain>",
   "aliases": [
    "mixedscript"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "cookies",
   "category": "web",
   "brief": "Audit Set-Cookie flags: Secure, HttpOnly, SameSite, prefixes and lifetimes.",
   "usage": "<url|host>",
   "aliases": [],
   "sources": [
    "direct HTTP"
   ]
  },
  {
   "name": "cors",
   "category": "web",
   "brief": "Probe the CORS policy with an untrusted Origin and a null Origin.",
   "usage": "<url|host>",
   "aliases": [
    "corscheck"
   ],
   "sources": [
    "direct HTTP"
   ]
  },
  {
   "name": "defang",
   "category": "web",
   "brief": "Defang URLs and indicators for safe sharing.",
   "usage": "defang <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "dehomoglyph",
   "category": "web",
   "brief": "Normalise lookalike characters back to ASCII.",
   "usage": "dehomoglyph <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "dorks",
   "category": "web",
   "brief": "Generate targeted search dorks for a domain (templates only, no queries sent).",
   "usage": "<domain>",
   "aliases": [
    "dork",
    "googledorks"
   ],
   "sources": [
    "local templates"
   ]
  },
  {
   "name": "expand",
   "category": "web",
   "brief": "Follow a short link or redirect chain hop by hop with status codes.",
   "usage": "<url>",
   "aliases": [
    "unshorten",
    "redirects"
   ],
   "sources": [
    "direct HTTP"
   ]
  },
  {
   "name": "favicon",
   "category": "web",
   "brief": "Favicon hashes for Shodan/Censys pivoting and origin clustering.",
   "usage": "<host>",
   "aliases": [
    "faviconhash"
   ],
   "sources": [
    "direct HTTP"
   ]
  },
  {
   "name": "homoglyph",
   "category": "web",
   "brief": "Render text with Unicode confusables.",
   "usage": "homoglyph <text>",
   "aliases": [
    "confuse"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "httphdr",
   "category": "web",
   "brief": "Explain an HTTP header.",
   "usage": "httphdr <header>",
   "aliases": [
    "headerinfo"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "iocs",
   "category": "web",
   "brief": "Extract indicators from pasted text.",
   "usage": "iocs <text>",
   "aliases": [
    "extractiocs"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "metatags",
   "category": "web",
   "brief": "Extract page metadata: title, description, OpenGraph, canonical and JSON-LD.",
   "usage": "<url|host>",
   "aliases": [
    "meta",
    "opengraph"
   ],
   "sources": [
    "direct HTTP"
   ]
  },
  {
   "name": "methods",
   "category": "web",
   "brief": "Allowed HTTP methods from an OPTIONS request.",
   "usage": "<url|host>",
   "aliases": [
    "options",
    "allow"
   ],
   "sources": [
    "direct HTTP"
   ]
  },
  {
   "name": "phish",
   "category": "web",
   "brief": "Heuristic phishing analysis of a URL without loading it.",
   "usage": "<url>",
   "aliases": [
    "phishing",
    "scam"
   ],
   "sources": [
    "local heuristics"
   ]
  },
  {
   "name": "phishdork",
   "category": "web",
   "brief": "Hunt dorks for lookalike infrastructure impersonating a brand.",
   "usage": "phishdork <brand>",
   "aliases": [
    "luredork"
   ],
   "sources": [
    "local heuristics"
   ]
  },
  {
   "name": "phishkit",
   "category": "web",
   "brief": "Fingerprint a phishing kit from an HTML or source snippet.",
   "usage": "phishkit <html snippet>",
   "aliases": [
    "kitcheck"
   ],
   "sources": [
    "local heuristics"
   ]
  },
  {
   "name": "phishlure",
   "category": "web",
   "brief": "Score a lure message for social-engineering markers.",
   "usage": "phishlure <message text>",
   "aliases": [
    "lurescore"
   ],
   "sources": [
    "local heuristics"
   ]
  },
  {
   "name": "phishmask",
   "category": "web",
   "brief": "Show the gap between a link's label and its real destination.",
   "usage": "phishmask <url>",
   "aliases": [
    "masklink"
   ],
   "sources": [
    "local heuristics"
   ]
  },
  {
   "name": "redirparams",
   "category": "web",
   "brief": "List redirect-style query parameters and their targets.",
   "usage": "redirparams <url>",
   "aliases": [
    "redir"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "refang",
   "category": "web",
   "brief": "Restore a defanged indicator.",
   "usage": "refang <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "robots",
   "category": "web",
   "brief": "Fetch and interpret robots.txt: crawl rules, sitemaps and sensitive paths.",
   "usage": "<host>",
   "aliases": [],
   "sources": [
    "direct HTTP"
   ]
  },
  {
   "name": "secheaders",
   "category": "web",
   "brief": "Grade HTTP security headers A–F with per-header reasoning.",
   "usage": "<url|host>",
   "aliases": [
    "headersecurity",
    "grade"
   ],
   "sources": [
    "direct HTTP"
   ]
  },
  {
   "name": "securitytxt",
   "category": "web",
   "brief": "Check RFC 9116 security.txt for contacts, policy and expiry.",
   "usage": "<host>",
   "aliases": [],
   "sources": [
    "direct HTTP"
   ]
  },
  {
   "name": "sitemap",
   "category": "web",
   "brief": "Parse sitemap.xml or a sitemap index for URL counts and samples.",
   "usage": "<host> [path]",
   "aliases": [],
   "sources": [
    "direct HTTP"
   ]
  },
  {
   "name": "tech",
   "category": "web",
   "brief": "Technology fingerprint from headers, cookies and markup with evidence.",
   "usage": "<url|host>",
   "aliases": [
    "whatweb",
    "stack"
   ],
   "sources": [
    "direct HTTP",
    "local signature tables"
   ]
  },
  {
   "name": "typosquat",
   "category": "web",
   "brief": "Enumerate lookalike domains for defensive registration.",
   "usage": "typosquat <domain>",
   "aliases": [
    "lookalike"
   ],
   "sources": [
    "local heuristics"
   ]
  },
  {
   "name": "url",
   "category": "web",
   "brief": "Full URL report: components, redirect chain, status, headers and a risk score.",
   "usage": "<url>",
   "aliases": [
    "urlinfo",
    "analyze"
   ],
   "sources": [
    "direct HTTP"
   ]
  },
  {
   "name": "urlentropy",
   "category": "web",
   "brief": "Measure host and path entropy for generated-looking URLs.",
   "usage": "urlentropy <url>",
   "aliases": [],
   "sources": [
    "local heuristics"
   ]
  },
  {
   "name": "urlunwrap",
   "category": "web",
   "brief": "Unwrap nested encodings and redirect parameters offline.",
   "usage": "urlunwrap <url>",
   "aliases": [
    "unwrap"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "waf",
   "category": "web",
   "brief": "Passive WAF fingerprint with challenge-page indicators.",
   "usage": "<host>",
   "aliases": [
    "firewall"
   ],
   "sources": [
    "direct HTTP"
   ]
  },
  {
   "name": "decode",
   "category": "identity",
   "brief": "Multi-format decoder: base64, hex, URL, HTML, binary, ROT13.",
   "usage": "<value>",
   "aliases": [
    "decoder",
    "unbase64"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "email",
   "category": "identity",
   "brief": "Email report: syntax, MX routing, disposable/free provider, Gravatar and breach status.",
   "usage": "<address>",
   "aliases": [
    "mailbox",
    "emailinfo"
   ],
   "sources": [
    "Cloudflare DoH",
    "Gravatar",
    "HIBP (optional key)"
   ]
  },
  {
   "name": "emailbreach",
   "category": "identity",
   "brief": "Full breach history for an email address from Have I Been Pwned.",
   "usage": "<address>",
   "aliases": [
    "breaches",
    "pwned"
   ],
   "sources": [
    "Have I Been Pwned"
   ]
  },
  {
   "name": "encode",
   "category": "identity",
   "brief": "Encode a value into base64, hex, URL, HTML, binary and ROT13.",
   "usage": "<value>",
   "aliases": [
    "encoder",
    "b64"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "gravatar",
   "category": "identity",
   "brief": "Gravatar profile and avatar resolution for an email hash.",
   "usage": "<email|md5 hash>",
   "aliases": [],
   "sources": [
    "gravatar.com"
   ]
  },
  {
   "name": "hash",
   "category": "identity",
   "brief": "Identify a hash format and optionally test a candidate plaintext.",
   "usage": "<hash> [candidate]",
   "aliases": [
    "hashid",
    "identify"
   ],
   "sources": [
    "local signature table",
    "hashlib"
   ]
  },
  {
   "name": "iban",
   "category": "identity",
   "brief": "Validate an IBAN: country length, structure and MOD-97 checksum.",
   "usage": "<iban>",
   "aliases": [
    "bank"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "jwt",
   "category": "identity",
   "brief": "Decode a JWT without verifying it: header, claims, expiry and algorithm.",
   "usage": "<token>",
   "aliases": [
    "jwtdecode"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "msisdn",
   "category": "identity",
   "brief": "Phone number anatomy: validity, carrier, region, type and timezone (no owner lookup).",
   "usage": "<number> [region]",
   "aliases": [
    "phone",
    "number"
   ],
   "sources": [
    "libphonenumber offline metadata"
   ]
  },
  {
   "name": "password",
   "category": "identity",
   "brief": "Offline password strength audit: entropy, patterns and crack-time estimates.",
   "usage": "<password>",
   "aliases": [
    "passstrength",
    "strength"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "pwnedpass",
   "category": "identity",
   "brief": "Check a password against the Pwned Passwords range API using k-anonymity.",
   "usage": "<password>",
   "aliases": [
    "pwnedpassword",
    "hibp-pass"
   ],
   "sources": [
    "api.pwnedpasswords.com"
   ]
  },
  {
   "name": "sshkey",
   "category": "identity",
   "brief": "SSH public key fingerprint and structural analysis.",
   "usage": "<ssh public key>",
   "aliases": [
    "ssh"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "timestamp",
   "category": "identity",
   "brief": "Convert between Unix time, ISO 8601, Discord timestamps and calendar fields.",
   "usage": "<unix|iso>",
   "aliases": [
    "time",
    "epoch"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "useragent",
   "category": "identity",
   "brief": "Parse a User-Agent string into browser, engine, OS and device class.",
   "usage": "<user agent>",
   "aliases": [
    "ua"
   ],
   "sources": [
    "local signature table"
   ]
  },
  {
   "name": "username",
   "category": "identity",
   "brief": "Enumerate one handle across 45 public platforms and classify each hit.",
   "usage": "<handle>",
   "aliases": [
    "usercheck",
    "handle"
   ],
   "sources": [
    "45 public profile endpoints"
   ]
  },
  {
   "name": "uuid",
   "category": "identity",
   "brief": "Decode a UUID: version, variant, embedded timestamp and node.",
   "usage": "<uuid>",
   "aliases": [
    "uuidlookup"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "bluesky",
   "category": "social",
   "brief": "Bluesky / AT Protocol profile: handle, DID, follow counts and labels.",
   "usage": "<handle|did>",
   "aliases": [
    "bsky"
   ],
   "sources": [
    "public.api.bsky.app"
   ]
  },
  {
   "name": "devto",
   "category": "social",
   "brief": "dev.to author profile including linked GitHub and Twitter handles.",
   "usage": "<username>",
   "aliases": [],
   "sources": [
    "dev.to/api"
   ]
  },
  {
   "name": "ghrepos",
   "category": "social",
   "brief": "Repository inventory for a GitHub account with language and popularity ranking.",
   "usage": "<username>",
   "aliases": [
    "repos"
   ],
   "sources": [
    "api.github.com"
   ]
  },
  {
   "name": "github",
   "category": "social",
   "brief": "GitHub profile: identity, company, location, activity, languages and star count.",
   "usage": "<username>",
   "aliases": [
    "gh"
   ],
   "sources": [
    "api.github.com"
   ]
  },
  {
   "name": "gitlab",
   "category": "social",
   "brief": "GitLab account lookup by username.",
   "usage": "<username>",
   "aliases": [
    "gl"
   ],
   "sources": [
    "gitlab.com/api/v4"
   ]
  },
  {
   "name": "hackernews",
   "category": "social",
   "brief": "Hacker News account: karma, join date, submission count and about text.",
   "usage": "<username>",
   "aliases": [
    "hn"
   ],
   "sources": [
    "hacker-news.firebaseio.com"
   ]
  },
  {
   "name": "keybase",
   "category": "social",
   "brief": "Keybase identity graph: proofs, devices and profile.",
   "usage": "<username>",
   "aliases": [
    "kb"
   ],
   "sources": [
    "keybase.io API"
   ]
  },
  {
   "name": "mastodon",
   "category": "social",
   "brief": "Mastodon account lookup on any instance: followers, join date and bio.",
   "usage": "<user@instance>",
   "aliases": [
    "fediverse"
   ],
   "sources": [
    "per-instance Mastodon API"
   ]
  },
  {
   "name": "minecraft",
   "category": "social",
   "brief": "Minecraft account: UUID, skin, cape and name history via Mojang.",
   "usage": "<username>",
   "aliases": [
    "mc",
    "mojang"
   ],
   "sources": [
    "api.mojang.com",
    "sessionserver.mojang.com"
   ]
  },
  {
   "name": "npm",
   "category": "social",
   "brief": "npm maintainer footprint: package count, names and latest releases.",
   "usage": "<username>",
   "aliases": [
    "npmjs"
   ],
   "sources": [
    "registry.npmjs.org"
   ]
  },
  {
   "name": "pypi",
   "category": "social",
   "brief": "PyPI package metadata: maintainer, project links, releases and classifiers.",
   "usage": "<package>",
   "aliases": [],
   "sources": [
    "pypi.org/pypi"
   ]
  },
  {
   "name": "reddit",
   "category": "social",
   "brief": "Reddit account: karma split, age, verification and moderator status.",
   "usage": "<username>",
   "aliases": [
    "reddituser"
   ],
   "sources": [
    "reddit.com JSON"
   ]
  },
  {
   "name": "redditsub",
   "category": "social",
   "brief": "Subreddit statistics: subscribers, creation date, classification and description.",
   "usage": "<subreddit>",
   "aliases": [
    "subreddit",
    "r"
   ],
   "sources": [
    "reddit.com JSON"
   ]
  },
  {
   "name": "roblox",
   "category": "social",
   "brief": "Roblox account: ID, creation date, verification, ban state and avatar.",
   "usage": "<username>",
   "aliases": [
    "rbx"
   ],
   "sources": [
    "users.roblox.com",
    "thumbnails.roblox.com"
   ]
  },
  {
   "name": "stackoverflow",
   "category": "social",
   "brief": "Stack Overflow reputation, badges and account age by numeric user ID.",
   "usage": "<user id>",
   "aliases": [
    "so"
   ],
   "sources": [
    "api.stackexchange.com"
   ]
  },
  {
   "name": "steam",
   "category": "social",
   "brief": "Steam profile: SteamID, bans, member since, location and top games.",
   "usage": "<vanity|steamid64>",
   "aliases": [
    "steamid"
   ],
   "sources": [
    "steamcommunity.com XML",
    "Steam Web API (optional key)"
   ]
  },
  {
   "name": "telegram",
   "category": "social",
   "brief": "Telegram public channel or user preview: title, bio and member count.",
   "usage": "<handle>",
   "aliases": [
    "tg"
   ],
   "sources": [
    "t.me preview"
   ]
  },
  {
   "name": "accountage",
   "category": "discord",
   "brief": "Account creation date and age from a Discord ID.",
   "usage": "<id|mention>",
   "aliases": [
    "idage",
    "created"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "avatar",
   "category": "discord",
   "brief": "Every CDN rendition of a user's avatar.",
   "usage": "<id|mention>",
   "aliases": [
    "pfp"
   ],
   "sources": [
    "Discord CDN"
   ]
  },
  {
   "name": "banner",
   "category": "discord",
   "brief": "Banner and accent colour for a Discord account.",
   "usage": "<id|mention>",
   "aliases": [
    "profilebanner"
   ],
   "sources": [
    "Discord REST API",
    "Discord CDN"
   ]
  },
  {
   "name": "emoji",
   "category": "discord",
   "brief": "Resolve a custom emoji to its CDN asset and metadata.",
   "usage": "<emoji>",
   "aliases": [
    "emojiinfo"
   ],
   "sources": [
    "local parse",
    "Discord CDN"
   ]
  },
  {
   "name": "fakesnowflake",
   "category": "discord",
   "brief": "Build a Discord snowflake for a timestamp.",
   "usage": "fakesnowflake [date]",
   "aliases": [
    "snowflakesynth"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "guildinfo",
   "category": "discord",
   "brief": "Guild summary for a server this bot is in.",
   "usage": "[guild id]",
   "aliases": [
    "serverinfo",
    "guild"
   ],
   "sources": [
    "Discord gateway cache"
   ]
  },
  {
   "name": "intents",
   "category": "discord",
   "brief": "Decode a gateway intents bitfield.",
   "usage": "intents <integer>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "invite",
   "category": "discord",
   "brief": "Invite intelligence: guild, channel, inviter, member counts and expiry.",
   "usage": "<code|invite link>",
   "aliases": [
    "inv"
   ],
   "sources": [
    "Discord REST API"
   ]
  },
  {
   "name": "oauthscopes",
   "category": "discord",
   "brief": "Explain Discord OAuth2 scopes.",
   "usage": "oauthscopes [scope]",
   "aliases": [
    "scopes"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "perms",
   "category": "discord",
   "brief": "Decode a Discord permission bitfield.",
   "usage": "perms <integer>",
   "aliases": [
    "permissions"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "sniperlist",
   "category": "discord",
   "brief": "List the active sniper watches on this instance.",
   "usage": "sniperlist",
   "aliases": [
    "watches",
    "snipe"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "sniperstop",
   "category": "discord",
   "brief": "Stop one sniper watch, or all of them.",
   "usage": "sniperstop <target|all>",
   "aliases": [
    "snipecancel"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "snowflake",
   "category": "discord",
   "brief": "Decompose a Discord snowflake into timestamp, worker, process and sequence.",
   "usage": "<id|message link>",
   "aliases": [
    "sf",
    "id"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "snowflakerange",
   "category": "discord",
   "brief": "Snowflake bounds for one UTC day.",
   "usage": "snowflakerange <date>",
   "aliases": [
    "snowflakeday"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "status",
   "category": "discord",
   "brief": "Live Discord platform status, degraded components and active incidents.",
   "usage": "status",
   "aliases": [
    "discordstatus",
    "dstatus"
   ],
   "sources": [
    "discordstatus.com"
   ]
  },
  {
   "name": "tokentype",
   "category": "discord",
   "brief": "Classify a token's shape without echoing it.",
   "usage": "tokentype <token>",
   "aliases": [
    "tokencheck"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "userinfo",
   "category": "discord",
   "brief": "Discord account summary: creation date, badges, avatar, banner and shared guilds.",
   "usage": "<id|mention>",
   "aliases": [
    "user",
    "whoisuser"
   ],
   "sources": [
    "Discord REST API"
   ]
  },
  {
   "name": "usernamecheck",
   "category": "discord",
   "brief": "Check whether a Discord username is still available.",
   "usage": "usernamecheck <username>",
   "aliases": [
    "ucheck",
    "useravail"
   ],
   "sources": [
    "discord username check"
   ]
  },
  {
   "name": "usernamesnipe",
   "category": "discord",
   "brief": "Watch a username and report the moment it frees up.",
   "usage": "usernamesnipe <username> [seconds]",
   "aliases": [
    "usersnipe",
    "usnipe"
   ],
   "sources": [
    "discord username check"
   ]
  },
  {
   "name": "vanitycheck",
   "category": "discord",
   "brief": "Check whether a Discord vanity URL is available.",
   "usage": "vanitycheck <code>",
   "aliases": [
    "vcheck",
    "vanity"
   ],
   "sources": [
    "discord invites api"
   ]
  },
  {
   "name": "vanitysnipe",
   "category": "discord",
   "brief": "Watch a vanity URL and report the moment it frees up.",
   "usage": "vanitysnipe <code> [seconds]",
   "aliases": [
    "vsnipe"
   ],
   "sources": [
    "discord invites api"
   ]
  },
  {
   "name": "vanitywatch",
   "category": "discord",
   "brief": "Check several vanity codes in one pass.",
   "usage": "vanitywatch <code> [code …]",
   "aliases": [
    "vbatch",
    "vanityscan"
   ],
   "sources": [
    "discord invites api"
   ]
  },
  {
   "name": "webhook",
   "category": "discord",
   "brief": "Webhook metadata from a webhook URL without executing it.",
   "usage": "<webhook url>",
   "aliases": [
    "wh"
   ],
   "sources": [
    "Discord REST API"
   ]
  },
  {
   "name": "abuseipdb",
   "category": "vuln",
   "brief": "AbuseIPDB reputation score and report breakdown for an IP.",
   "usage": "<ip>",
   "aliases": [
    "abuseip"
   ],
   "sources": [
    "AbuseIPDB API"
   ]
  },
  {
   "name": "bazaar",
   "category": "vuln",
   "brief": "MalwareBazaar sample metadata for a file hash.",
   "usage": "<hash>",
   "aliases": [
    "malwarebazaar",
    "sample"
   ],
   "sources": [
    "abuse.ch MalwareBazaar"
   ]
  },
  {
   "name": "cve",
   "category": "vuln",
   "brief": "Full CVE report: description, CVSS, CWE, CPE exposure, EPSS and KEV status.",
   "usage": "<cve id>",
   "aliases": [
    "cveinfo",
    "vuln"
   ],
   "sources": [
    "NIST NVD",
    "FIRST EPSS",
    "CISA KEV"
   ]
  },
  {
   "name": "cvesearch",
   "category": "vuln",
   "brief": "Keyword search across the NVD CVE corpus.",
   "usage": "<keyword>",
   "aliases": [
    "searchcve"
   ],
   "sources": [
    "NIST NVD"
   ]
  },
  {
   "name": "cvss",
   "category": "vuln",
   "brief": "Calculate a CVSS v3 base score from a vector string.",
   "usage": "<vector>",
   "aliases": [
    "cvsscalc"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "cwe",
   "category": "vuln",
   "brief": "CWE weakness definition, consequences and mitigations.",
   "usage": "<cwe id>",
   "aliases": [
    "weakness"
   ],
   "sources": [
    "cwe-api.mitre.org"
   ]
  },
  {
   "name": "epss",
   "category": "vuln",
   "brief": "EPSS exploitation probability for a CVE with percentile context.",
   "usage": "<cve>",
   "aliases": [
    "exploitprob"
   ],
   "sources": [
    "FIRST EPSS"
   ]
  },
  {
   "name": "kev",
   "category": "vuln",
   "brief": "Search the CISA Known Exploited Vulnerabilities catalogue.",
   "usage": "<cve|product>",
   "aliases": [
    "known-exploited"
   ],
   "sources": [
    "CISA KEV"
   ]
  },
  {
   "name": "nvdrecent",
   "category": "vuln",
   "brief": "CVEs published in the last seven days, ranked by CVSS.",
   "usage": "nvdrecent",
   "aliases": [
    "recentcves",
    "latest"
   ],
   "sources": [
    "NIST NVD"
   ]
  },
  {
   "name": "shodan",
   "category": "vuln",
   "brief": "Shodan host exposure: open ports, banners, hostnames and known vulnerabilities.",
   "usage": "<ip>",
   "aliases": [
    "shodanhost"
   ],
   "sources": [
    "Shodan API"
   ]
  },
  {
   "name": "urlscan",
   "category": "vuln",
   "brief": "Passive urlscan.io search for scans touching a domain, IP or hash.",
   "usage": "<indicator>",
   "aliases": [],
   "sources": [
    "urlscan.io API"
   ]
  },
  {
   "name": "virustotal",
   "category": "vuln",
   "brief": "VirusTotal multi-engine reputation for an IP, domain, URL or hash.",
   "usage": "<indicator>",
   "aliases": [
    "vt"
   ],
   "sources": [
    "VirusTotal API v3"
   ]
  },
  {
   "name": "address",
   "category": "crypto",
   "brief": "Classify an address across 15 chain formats and validate what can be validated locally.",
   "usage": "<address>",
   "aliases": [
    "coin",
    "detect"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "block",
   "category": "crypto",
   "brief": "Bitcoin block header and statistics by height or hash.",
   "usage": "<height|hash>",
   "aliases": [
    "btcblock"
   ],
   "sources": [
    "blockstream.info"
   ]
  },
  {
   "name": "btc",
   "category": "crypto",
   "brief": "Bitcoin address summary: balance, lifetime flows, transaction count and recent activity.",
   "usage": "<address>",
   "aliases": [
    "btcaddr"
   ],
   "sources": [
    "blockstream.info"
   ]
  },
  {
   "name": "btctx",
   "category": "crypto",
   "brief": "Bitcoin transaction detail: confirmations, fee, inputs and outputs.",
   "usage": "<txid>",
   "aliases": [
    "tx"
   ],
   "sources": [
    "blockstream.info"
   ]
  },
  {
   "name": "eth",
   "category": "crypto",
   "brief": "Ethereum account state: balance, nonce, contract status and activity.",
   "usage": "<address>",
   "aliases": [
    "ethaddr"
   ],
   "sources": [
    "cloudflare-eth.com"
   ]
  },
  {
   "name": "ethtx",
   "category": "crypto",
   "brief": "Ethereum transaction and receipt: sender, recipient, value, gas and status.",
   "usage": "<tx hash>",
   "aliases": [],
   "sources": [
    "cloudflare-eth.com"
   ]
  },
  {
   "name": "sol",
   "category": "crypto",
   "brief": "Solana account balance and recent signature history.",
   "usage": "<address>",
   "aliases": [
    "solana"
   ],
   "sources": [
    "api.mainnet-beta.solana.com"
   ]
  },
  {
   "name": "a1z26",
   "category": "craft",
   "brief": "Encode letters as 1–26 numbers.",
   "usage": "a1z26 <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "acrostic",
   "category": "craft",
   "brief": "Read the first letter of every line.",
   "usage": "acrostic <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "anagram",
   "category": "craft",
   "brief": "Compare two strings as anagrams.",
   "usage": "anagram <left|right>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "atbash",
   "category": "craft",
   "brief": "Apply the Atbash letter reversal.",
   "usage": "atbash <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "b64url",
   "category": "craft",
   "brief": "Encode text as URL-safe base64.",
   "usage": "b64url <text>",
   "aliases": [
    "base64url"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "bacon",
   "category": "craft",
   "brief": "Encode letters as Bacon's A/B groups.",
   "usage": "bacon <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "base36",
   "category": "craft",
   "brief": "Encode text as base36.",
   "usage": "base36 <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "base58",
   "category": "craft",
   "brief": "Encode text as base58 (Bitcoin alphabet).",
   "usage": "base58 <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "base85",
   "category": "craft",
   "brief": "Encode text as base85.",
   "usage": "base85 <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "bitreverse",
   "category": "craft",
   "brief": "Reverse the bit order of every byte.",
   "usage": "bitreverse <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "caesar",
   "category": "craft",
   "brief": "Shift letters with a Caesar rotation.",
   "usage": "caesar <shift|text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "freq",
   "category": "craft",
   "brief": "Character frequency table.",
   "usage": "freq <text>",
   "aliases": [
    "frequency"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "fromhexdump",
   "category": "craft",
   "brief": "Rebuild text from a hex dump.",
   "usage": "fromhexdump <dump>",
   "aliases": [
    "unxxd"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "hexdump",
   "category": "craft",
   "brief": "Show offset, hex and ASCII for any text.",
   "usage": "hexdump <text>",
   "aliases": [
    "xxd"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "leet",
   "category": "craft",
   "brief": "Convert text to leetspeak.",
   "usage": "leet <text>",
   "aliases": [
    "1337"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "nato",
   "category": "craft",
   "brief": "Spell text with the NATO alphabet.",
   "usage": "nato <text>",
   "aliases": [
    "phonetic"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "ngrams",
   "category": "craft",
   "brief": "Top bigrams and trigrams.",
   "usage": "ngrams <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "palindrome",
   "category": "craft",
   "brief": "Test whether text is a palindrome.",
   "usage": "palindrome <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "passwordpolicy",
   "category": "craft",
   "brief": "Evaluate a password against policy rules.",
   "usage": "passwordpolicy <password>",
   "aliases": [
    "passrules"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "railfence",
   "category": "craft",
   "brief": "Rail-fence encode with N rails.",
   "usage": "railfence <rails|text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "readability",
   "category": "craft",
   "brief": "Flesch reading ease and grade level.",
   "usage": "readability <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "rot47",
   "category": "craft",
   "brief": "Apply the self-inverse ROT47 rotation.",
   "usage": "rot47 <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "stripzero",
   "category": "craft",
   "brief": "Remove zero-width characters.",
   "usage": "stripzero <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "una1z26",
   "category": "craft",
   "brief": "Decode 1–26 numbers to letters.",
   "usage": "una1z26 <numbers>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "unb64url",
   "category": "craft",
   "brief": "Decode URL-safe base64.",
   "usage": "unb64url <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "unbacon",
   "category": "craft",
   "brief": "Decode Bacon's A/B groups.",
   "usage": "unbacon <bits>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "unbase36",
   "category": "craft",
   "brief": "Decode base36 text.",
   "usage": "unbase36 <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "unbase58",
   "category": "craft",
   "brief": "Decode base58 text.",
   "usage": "unbase58 <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "unbase85",
   "category": "craft",
   "brief": "Decode base85 text.",
   "usage": "unbase85 <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "uncaesar",
   "category": "craft",
   "brief": "Print all 26 Caesar rotations.",
   "usage": "uncaesar <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "unicodeescape",
   "category": "craft",
   "brief": "Escape text as \\uXXXX sequences.",
   "usage": "unicodeescape <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "unleet",
   "category": "craft",
   "brief": "Approximate leetspeak decoding.",
   "usage": "unleet <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "unnato",
   "category": "craft",
   "brief": "Decode NATO alphabet words.",
   "usage": "unnato <words>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "unrailfence",
   "category": "craft",
   "brief": "Rail-fence decode with N rails.",
   "usage": "unrailfence <rails|text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "ununicode",
   "category": "craft",
   "brief": "Decode escape sequences.",
   "usage": "ununicode <escaped>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "unvigenere",
   "category": "craft",
   "brief": "Vigenère-decrypt with a keyword.",
   "usage": "unvigenere <key|text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "vigenere",
   "category": "craft",
   "brief": "Vigenère-encrypt with a keyword.",
   "usage": "vigenere <key|text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "wordfreq",
   "category": "craft",
   "brief": "Most common words with counts.",
   "usage": "wordfreq <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "xorhex",
   "category": "craft",
   "brief": "XOR text with a hex key.",
   "usage": "xorhex <keyhex|text>",
   "aliases": [
    "xor"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "zerowidth",
   "category": "craft",
   "brief": "Reveal zero-width and invisible characters.",
   "usage": "zerowidth <text>",
   "aliases": [
    "invisible"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "adler32",
   "category": "toolkit",
   "brief": "Adler-32 checksum.",
   "usage": "adler32 <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "b32d",
   "category": "toolkit",
   "brief": "Decode a base32 string.",
   "usage": "b32d <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "b32e",
   "category": "toolkit",
   "brief": "Base32-encode a UTF-8 string.",
   "usage": "b32e <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "b64d",
   "category": "toolkit",
   "brief": "Decode a base64 string.",
   "usage": "b64d <text>",
   "aliases": [
    "b64decode"
   ],
   "sources": []
  },
  {
   "name": "b64e",
   "category": "toolkit",
   "brief": "Base64-encode a UTF-8 string.",
   "usage": "b64e <text>",
   "aliases": [
    "b64encode"
   ],
   "sources": []
  },
  {
   "name": "base64check",
   "category": "toolkit",
   "brief": "Check whether a string is valid base64.",
   "usage": "base64check <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "baseconvert",
   "category": "toolkit",
   "brief": "Convert a number between bases: `from|to|number`.",
   "usage": "baseconvert <from|to|number>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "blake2b",
   "category": "toolkit",
   "brief": "BLAKE2b digest of a string.",
   "usage": "blake2b <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "bytecount",
   "category": "toolkit",
   "brief": "Show UTF-8, base64 and hex sizes.",
   "usage": "bytecount <text>",
   "aliases": [
    "bytes"
   ],
   "sources": []
  },
  {
   "name": "caseconv",
   "category": "toolkit",
   "brief": "Convert between naming styles.",
   "usage": "caseconv <style|text>",
   "aliases": [
    "casing"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "charcount",
   "category": "toolkit",
   "brief": "Count characters and lines.",
   "usage": "charcount <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "cidrcontains",
   "category": "toolkit",
   "brief": "Test whether an address is inside a block.",
   "usage": "cidrcontains <cidr|address>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "cidrmerge",
   "category": "toolkit",
   "brief": "Collapse overlapping CIDR blocks.",
   "usage": "cidrmerge <cidrs>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "cidrsplit",
   "category": "toolkit",
   "brief": "Split a CIDR block: `cidr|prefix`.",
   "usage": "cidrsplit <cidr|prefix>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "codepoints",
   "category": "toolkit",
   "brief": "Show the Unicode code point of each character.",
   "usage": "codepoints <text>",
   "aliases": [
    "unicode"
   ],
   "sources": []
  },
  {
   "name": "colorblind",
   "category": "toolkit",
   "brief": "Simulate a hex colour under colour-vision deficiencies.",
   "usage": "colorblind <#hex>",
   "aliases": [
    "cvd"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "contrast",
   "category": "toolkit",
   "brief": "Calculate WCAG contrast between two colours.",
   "usage": "contrast <#hex> <#hex>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "cookieparse",
   "category": "toolkit",
   "brief": "Break a Set-Cookie value into pairs.",
   "usage": "cookieparse <cookie>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "crc32",
   "category": "toolkit",
   "brief": "CRC-32 checksum of a string.",
   "usage": "crc32 <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "crondesc",
   "category": "toolkit",
   "brief": "Explain a cron expression.",
   "usage": "crondesc <expression>",
   "aliases": [
    "cron"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "csp",
   "category": "toolkit",
   "brief": "List Content-Security-Policy directives.",
   "usage": "csp <policy>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "csvjson",
   "category": "toolkit",
   "brief": "Convert CSV with a header row to JSON.",
   "usage": "csvjson <csv>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "csvtable",
   "category": "toolkit",
   "brief": "Convert CSV into a Markdown table.",
   "usage": "csvtable <csv>",
   "aliases": [
    "csvmd"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "dedupe",
   "category": "toolkit",
   "brief": "Remove duplicate lines while preserving order.",
   "usage": "dedupe <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "difftext",
   "category": "toolkit",
   "brief": "Unified diff between `left|right`.",
   "usage": "difftext <left|right>",
   "aliases": [
    "diff"
   ],
   "sources": []
  },
  {
   "name": "domaincheck",
   "category": "toolkit",
   "brief": "Validate a domain and show its registrable form.",
   "usage": "domaincheck <domain>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "duration",
   "category": "toolkit",
   "brief": "Format a number of seconds as days and clock time.",
   "usage": "duration <seconds>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "emailcheck",
   "category": "toolkit",
   "brief": "Validate an email address structurally.",
   "usage": "emailcheck <email>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "entropy",
   "category": "toolkit",
   "brief": "Measure Shannon entropy of text.",
   "usage": "entropy <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "epochtime",
   "category": "toolkit",
   "brief": "Convert epoch seconds, millis or a date.",
   "usage": "epochtime <value>",
   "aliases": [
    "epochms"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "factors",
   "category": "toolkit",
   "brief": "List every factor of a number.",
   "usage": "factors <number>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "fib",
   "category": "toolkit",
   "brief": "Print Fibonacci terms.",
   "usage": "fib <count>",
   "aliases": [
    "fibonacci"
   ],
   "sources": []
  },
  {
   "name": "fnv1a",
   "category": "toolkit",
   "brief": "FNV-1a 32- and 64-bit hashes.",
   "usage": "fnv1a <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "frombin",
   "category": "toolkit",
   "brief": "Decode binary bytes to UTF-8.",
   "usage": "frombin <bits>",
   "aliases": [
    "unbinary"
   ],
   "sources": []
  },
  {
   "name": "fromcodepoints",
   "category": "toolkit",
   "brief": "Build text from Unicode code points.",
   "usage": "fromcodepoints <points>",
   "aliases": [
    "ununicode"
   ],
   "sources": []
  },
  {
   "name": "gcd",
   "category": "toolkit",
   "brief": "Greatest common divisor of two or more numbers.",
   "usage": "gcd <a> <b>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "hashident",
   "category": "toolkit",
   "brief": "Identify a hash by length and prefix.",
   "usage": "hashident <hash>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "hashmode",
   "category": "toolkit",
   "brief": "Suggest hashcat modes for a hash.",
   "usage": "hashmode <hash>",
   "aliases": [
    "hashcat"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "hexd",
   "category": "toolkit",
   "brief": "Decode hexadecimal bytes to text.",
   "usage": "hexd <hex>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "hexe",
   "category": "toolkit",
   "brief": "Encode text as hexadecimal bytes.",
   "usage": "hexe <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "hexrgb",
   "category": "toolkit",
   "brief": "Convert a hex colour to RGB and HSL.",
   "usage": "hexrgb <#hex>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "hmacmd5",
   "category": "toolkit",
   "brief": "HMAC-MD5 of `key|message`.",
   "usage": "hmacmd5 <key|message>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "hmacsha1",
   "category": "toolkit",
   "brief": "HMAC-SHA1 of `key|message`.",
   "usage": "hmacsha1 <key|message>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "hmacsha256",
   "category": "toolkit",
   "brief": "HMAC-SHA256 of `key|message`.",
   "usage": "hmacsha256 <key|message>",
   "aliases": [
    "hmac"
   ],
   "sources": []
  },
  {
   "name": "hmacsha512",
   "category": "toolkit",
   "brief": "HMAC-SHA512 of `key|message`.",
   "usage": "hmacsha512 <key|message>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "hsts",
   "category": "toolkit",
   "brief": "Parse Strict-Transport-Security directives.",
   "usage": "hsts <header>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "htmlenc",
   "category": "toolkit",
   "brief": "Escape text for HTML.",
   "usage": "htmlenc <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "htmlunesc",
   "category": "toolkit",
   "brief": "Unescape HTML entities.",
   "usage": "htmlunesc <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "httpdate",
   "category": "toolkit",
   "brief": "Parse an HTTP date header.",
   "usage": "httpdate <date>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "httpmethod",
   "category": "toolkit",
   "brief": "Describe an HTTP method.",
   "usage": "httpmethod <method>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "int2ip",
   "category": "toolkit",
   "brief": "Convert a 32-bit integer to IPv4.",
   "usage": "int2ip <integer>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "ip2int",
   "category": "toolkit",
   "brief": "Convert IPv4 to its 32-bit integer.",
   "usage": "ip2int <ipv4>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "ipcheck",
   "category": "toolkit",
   "brief": "Validate an IP address and show its flags.",
   "usage": "ipcheck <ip>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "ipclass",
   "category": "toolkit",
   "brief": "Classify an address and its flags.",
   "usage": "ipclass <ip>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "ipv4range",
   "category": "toolkit",
   "brief": "Describe an inclusive IPv4 range.",
   "usage": "ipv4range <first|last>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "ipv6compress",
   "category": "toolkit",
   "brief": "Compress an IPv6 address.",
   "usage": "ipv6compress <ipv6>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "ipv6expand",
   "category": "toolkit",
   "brief": "Expand an IPv6 address.",
   "usage": "ipv6expand <ipv6>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "ipv6range",
   "category": "toolkit",
   "brief": "Describe an inclusive IPv6 range.",
   "usage": "ipv6range <first|last>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "isbncheck",
   "category": "toolkit",
   "brief": "Validate an ISBN-10 or ISBN-13.",
   "usage": "isbncheck <isbn>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "johnmode",
   "category": "toolkit",
   "brief": "Suggest a John the Ripper format for a hash.",
   "usage": "johnmode <hash>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "jsoncheck",
   "category": "toolkit",
   "brief": "Validate JSON and report its type.",
   "usage": "jsoncheck <json>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "jsonflat",
   "category": "toolkit",
   "brief": "Flatten JSON into dotted paths.",
   "usage": "jsonflat <json>",
   "aliases": [
    "jsonpaths"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "jsonfmt",
   "category": "toolkit",
   "brief": "Pretty-print JSON.",
   "usage": "jsonfmt <json>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "jsonkeys",
   "category": "toolkit",
   "brief": "List every key path in JSON.",
   "usage": "jsonkeys <json>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "jsonmin",
   "category": "toolkit",
   "brief": "Minify JSON.",
   "usage": "jsonmin <json>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "jsonvals",
   "category": "toolkit",
   "brief": "Show top-level JSON values.",
   "usage": "jsonvals <json>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "jwtcheck",
   "category": "toolkit",
   "brief": "Check JWT shape and algorithm.",
   "usage": "jwtcheck <token>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "jwtinspect",
   "category": "toolkit",
   "brief": "Decode JWT header and payload without verifying.",
   "usage": "jwtinspect <token>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "jwtpayload",
   "category": "toolkit",
   "brief": "Show only a JWT payload.",
   "usage": "jwtpayload <token>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "lcm",
   "category": "toolkit",
   "brief": "Least common multiple of two or more numbers.",
   "usage": "lcm <a> <b>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "linenums",
   "category": "toolkit",
   "brief": "Add line numbers to text.",
   "usage": "linenums <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "linewrap",
   "category": "toolkit",
   "brief": "Wrap text at a chosen width: `width|text`.",
   "usage": "linewrap <width|text>",
   "aliases": [
    "wrap"
   ],
   "sources": []
  },
  {
   "name": "lowercase",
   "category": "toolkit",
   "brief": "Convert text to lowercase.",
   "usage": "lowercase <text>",
   "aliases": [
    "lower"
   ],
   "sources": []
  },
  {
   "name": "luhn",
   "category": "toolkit",
   "brief": "Validate a number with the Luhn checksum.",
   "usage": "luhn <number>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "macfmt",
   "category": "toolkit",
   "brief": "Normalise a MAC address into three formats.",
   "usage": "macfmt <mac>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "md5",
   "category": "toolkit",
   "brief": "MD5 digest of a string.",
   "usage": "md5 <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "mean",
   "category": "toolkit",
   "brief": "Arithmetic mean of a list of numbers.",
   "usage": "mean <numbers>",
   "aliases": [
    "average"
   ],
   "sources": []
  },
  {
   "name": "median",
   "category": "toolkit",
   "brief": "Median of a list of numbers.",
   "usage": "median <numbers>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "mime",
   "category": "toolkit",
   "brief": "Look up a MIME type or extension.",
   "usage": "mime <mime|extension>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "mode",
   "category": "toolkit",
   "brief": "Most common number in a list.",
   "usage": "mode <numbers>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "morse",
   "category": "toolkit",
   "brief": "Encode text as International Morse.",
   "usage": "morse <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "murmur3",
   "category": "toolkit",
   "brief": "MurmurHash3 x86 32-bit — the favicon pivot hash.",
   "usage": "murmur3 <text>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "numrange",
   "category": "toolkit",
   "brief": "Difference between the largest and smallest number.",
   "usage": "numrange <numbers>",
   "aliases": [
    "span"
   ],
   "sources": []
  },
  {
   "name": "offsettime",
   "category": "toolkit",
   "brief": "Show one instant across time zones.",
   "usage": "offsettime <timestamp>",
   "aliases": [
    "tz"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "passwordbits",
   "category": "toolkit",
   "brief": "Estimate password strength without storing it.",
   "usage": "passwordbits <password>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "pbkdf2",
   "category": "toolkit",
   "brief": "Derive a key with PBKDF2-HMAC-SHA256.",
   "usage": "pbkdf2 <salt|password>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "percent",
   "category": "toolkit",
   "brief": "Calculate `part|whole` as a percentage.",
   "usage": "percent <part|whole>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "portmap",
   "category": "toolkit",
   "brief": "Map a port number to a common service, or search by name.",
   "usage": "portmap <port|service>",
   "aliases": [
    "portservice"
   ],
   "sources": []
  },
  {
   "name": "prime",
   "category": "toolkit",
   "brief": "Test whether a number is prime.",
   "usage": "prime <number>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "protocol",
   "category": "toolkit",
   "brief": "Map an IP protocol number to its name.",
   "usage": "protocol <number|name>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "ptrsuffix",
   "category": "toolkit",
   "brief": "Build the reverse-DNS name for an address.",
   "usage": "ptrsuffix <ip>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "puny",
   "category": "toolkit",
   "brief": "Convert a domain to its IDNA form.",
   "usage": "puny <domain>",
   "aliases": [
    "punycode"
   ],
   "sources": []
  },
  {
   "name": "querybuild",
   "category": "toolkit",
   "brief": "Encode key/value pairs as a query string.",
   "usage": "querybuild <pairs>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "queryparse",
   "category": "toolkit",
   "brief": "Parse a query string.",
   "usage": "queryparse <query>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "randomcolor",
   "category": "toolkit",
   "brief": "Generate one or more random hex colours.",
   "usage": "randomcolor [count]",
   "aliases": [
    "randcolor"
   ],
   "sources": []
  },
  {
   "name": "regexplain",
   "category": "toolkit",
   "brief": "Explain the constructs in a regular expression.",
   "usage": "regexplain <pattern>",
   "aliases": [
    "regexdebug"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "reverse",
   "category": "toolkit",
   "brief": "Reverse a string.",
   "usage": "reverse <text>",
   "aliases": [
    "reversetext"
   ],
   "sources": []
  },
  {
   "name": "rgbhex",
   "category": "toolkit",
   "brief": "Convert RGB channels to hex.",
   "usage": "rgbhex <r> <g> <b>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "roman",
   "category": "toolkit",
   "brief": "Convert an integer to a Roman numeral.",
   "usage": "roman <1-3999>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "rot13",
   "category": "toolkit",
   "brief": "Apply the ROT13 substitution.",
   "usage": "rot13 <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "semver",
   "category": "toolkit",
   "brief": "Validate and decompose a semantic version.",
   "usage": "semver <version>",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "sha1",
   "category": "toolkit",
   "brief": "SHA-1 digest of a string.",
   "usage": "sha1 <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "sha256",
   "category": "toolkit",
   "brief": "SHA-256 digest of a string.",
   "usage": "sha256 <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "sha3",
   "category": "toolkit",
   "brief": "SHA3-256 digest of a string.",
   "usage": "sha3 <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "sha512",
   "category": "toolkit",
   "brief": "SHA-512 digest of a string.",
   "usage": "sha512 <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "slug",
   "category": "toolkit",
   "brief": "Convert text to a URL-safe slug.",
   "usage": "slug <text>",
   "aliases": [
    "slugify"
   ],
   "sources": []
  },
  {
   "name": "sortlines",
   "category": "toolkit",
   "brief": "Sort lines alphabetically.",
   "usage": "sortlines <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "sortnums",
   "category": "toolkit",
   "brief": "Sort numbers in ascending order.",
   "usage": "sortnums <numbers>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "statuscode",
   "category": "toolkit",
   "brief": "Explain an HTTP status code.",
   "usage": "statuscode <code>",
   "aliases": [
    "httpcode"
   ],
   "sources": []
  },
  {
   "name": "striphtml",
   "category": "toolkit",
   "brief": "Remove HTML tags and decode entities.",
   "usage": "striphtml <html>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "sum",
   "category": "toolkit",
   "brief": "Sum a list of numbers.",
   "usage": "sum <numbers>",
   "aliases": [
    "addnums"
   ],
   "sources": []
  },
  {
   "name": "swapcase",
   "category": "toolkit",
   "brief": "Swap the case of every character.",
   "usage": "swapcase <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "textstats",
   "category": "toolkit",
   "brief": "Count characters, words, lines and unique words.",
   "usage": "textstats <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "titlecase",
   "category": "toolkit",
   "brief": "Convert text to title case.",
   "usage": "titlecase <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "tobin",
   "category": "toolkit",
   "brief": "Render UTF-8 bytes as binary.",
   "usage": "tobin <text>",
   "aliases": [
    "binary"
   ],
   "sources": []
  },
  {
   "name": "ts",
   "category": "toolkit",
   "brief": "Parse a timestamp into every useful format.",
   "usage": "ts <timestamp>",
   "aliases": [
    "timestampinfo"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "unix",
   "category": "toolkit",
   "brief": "Convert a Unix timestamp, or show the current time.",
   "usage": "unix [timestamp]",
   "aliases": [
    "timestamp"
   ],
   "sources": []
  },
  {
   "name": "unixdate",
   "category": "toolkit",
   "brief": "Convert a date to a Unix timestamp.",
   "usage": "unixdate <date>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "unmorse",
   "category": "toolkit",
   "brief": "Decode International Morse.",
   "usage": "unmorse <morse>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "unpuny",
   "category": "toolkit",
   "brief": "Decode an IDNA domain.",
   "usage": "unpuny <domain>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "unroman",
   "category": "toolkit",
   "brief": "Convert a Roman numeral to an integer.",
   "usage": "unroman <numeral>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "uppercase",
   "category": "toolkit",
   "brief": "Convert text to uppercase.",
   "usage": "uppercase <text>",
   "aliases": [
    "upper"
   ],
   "sources": []
  },
  {
   "name": "urld",
   "category": "toolkit",
   "brief": "Decode percent-encoded text.",
   "usage": "urld <text>",
   "aliases": [
    "urldecode"
   ],
   "sources": []
  },
  {
   "name": "urle",
   "category": "toolkit",
   "brief": "Percent-encode text for a URL component.",
   "usage": "urle <text>",
   "aliases": [
    "urlencode"
   ],
   "sources": []
  },
  {
   "name": "urlinspect",
   "category": "toolkit",
   "brief": "Break a URL into scheme, host, path and query.",
   "usage": "urlinspect <url>",
   "aliases": [
    "urlparse"
   ],
   "sources": []
  },
  {
   "name": "useragentparse",
   "category": "toolkit",
   "brief": "Inspect a User-Agent string.",
   "usage": "useragentparse <user-agent>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "uuidcheck",
   "category": "toolkit",
   "brief": "Validate a UUID and report its variant.",
   "usage": "uuidcheck <uuid>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "weekday",
   "category": "toolkit",
   "brief": "Show the weekday and ISO week for a date.",
   "usage": "weekday <date>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "wildcardmask",
   "category": "toolkit",
   "brief": "Show the Cisco wildcard mask for IPv4.",
   "usage": "wildcardmask <cidr>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "wordcount",
   "category": "toolkit",
   "brief": "Count words in text.",
   "usage": "wordcount <text>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "fakecard",
   "category": "generator",
   "brief": "Generate a Luhn-valid synthetic card number.",
   "usage": "fakecard [bin prefix]",
   "aliases": [
    "testcard"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "fakehash",
   "category": "generator",
   "brief": "Generate a hex hash of a chosen length.",
   "usage": "fakehash [length]",
   "aliases": [
    "testhash"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "fakeiban",
   "category": "generator",
   "brief": "Generate a MOD-97-valid synthetic IBAN.",
   "usage": "fakeiban [country]",
   "aliases": [
    "testiban"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "fakeimei",
   "category": "generator",
   "brief": "Generate a Luhn-valid synthetic IMEI.",
   "usage": "fakeimei [tac]",
   "aliases": [
    "testimei"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "fakejwt",
   "category": "generator",
   "brief": "Build an unsigned demo JWT.",
   "usage": "fakejwt [subject]",
   "aliases": [
    "testjwt"
   ],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "gen address",
   "category": "generator",
   "brief": "Generate a fictional postal address.",
   "usage": "gen address",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen apikey",
   "category": "generator",
   "brief": "Generate a random test API token.",
   "usage": "gen apikey",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen color",
   "category": "generator",
   "brief": "Generate a random hex colour.",
   "usage": "gen color",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen company",
   "category": "generator",
   "brief": "Generate a fictional company name.",
   "usage": "gen company",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen domain",
   "category": "generator",
   "brief": "Generate a reserved example domain.",
   "usage": "gen domain",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen email",
   "category": "generator",
   "brief": "Generate a synthetic email address.",
   "usage": "gen email [[domain]]",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen handle",
   "category": "generator",
   "brief": "Generate a synthetic social handle.",
   "usage": "gen handle",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen ipv4",
   "category": "generator",
   "brief": "Generate a documentation-range IPv4 address.",
   "usage": "gen ipv4",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen ipv6",
   "category": "generator",
   "brief": "Generate a documentation-range IPv6 address.",
   "usage": "gen ipv6",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen isbn",
   "category": "generator",
   "brief": "Generate a valid synthetic ISBN-13.",
   "usage": "gen isbn",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen job",
   "category": "generator",
   "brief": "Generate a fictional job title.",
   "usage": "gen job",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen lorem",
   "category": "generator",
   "brief": "Generate a short placeholder sentence.",
   "usage": "gen lorem",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen mac",
   "category": "generator",
   "brief": "Generate a locally administered MAC address.",
   "usage": "gen mac",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen name",
   "category": "generator",
   "brief": "Generate a fictional person's name.",
   "usage": "gen name",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen otp",
   "category": "generator",
   "brief": "Generate a six-digit test code.",
   "usage": "gen otp",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen passphrase",
   "category": "generator",
   "brief": "Generate a hyphenated passphrase.",
   "usage": "gen passphrase [[words]]",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen password",
   "category": "generator",
   "brief": "Generate a strong random password.",
   "usage": "gen password [[length]]",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen phone",
   "category": "generator",
   "brief": "Generate a reserved-range phone number.",
   "usage": "gen phone [[region]]",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen ulid",
   "category": "generator",
   "brief": "Generate a ULID.",
   "usage": "gen ulid",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen useragent",
   "category": "generator",
   "brief": "Return a realistic browser User-Agent string.",
   "usage": "gen useragent",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen username",
   "category": "generator",
   "brief": "Generate a synthetic username.",
   "usage": "gen username",
   "aliases": [],
   "sources": []
  },
  {
   "name": "gen uuid",
   "category": "generator",
   "brief": "Generate a random UUIDv4.",
   "usage": "gen uuid",
   "aliases": [],
   "sources": []
  },
  {
   "name": "nanoid",
   "category": "generator",
   "brief": "Generate a URL-safe random identifier.",
   "usage": "nanoid [length]",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "uuid7",
   "category": "generator",
   "brief": "Generate a time-ordered UUIDv7.",
   "usage": "uuid7 [date]",
   "aliases": [],
   "sources": [
    "local computation"
   ]
  },
  {
   "name": "about",
   "category": "system",
   "brief": "Version, scope and responsible-use notice.",
   "usage": "about",
   "aliases": [],
   "sources": []
  },
  {
   "name": "accessexport",
   "category": "system",
   "brief": "Export the configuration as one pasteable block for the console.",
   "usage": "accessexport",
   "aliases": [],
   "sources": []
  },
  {
   "name": "accessfields",
   "category": "system",
   "brief": "List every configuration field, its type and its current value.",
   "usage": "accessfields",
   "aliases": [],
   "sources": []
  },
  {
   "name": "accessimport",
   "category": "system",
   "brief": "Apply a configuration exported by the website console.",
   "usage": "<export>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "accesskey",
   "category": "system",
   "brief": "Issue, rotate, revoke or display the console pairing key.",
   "usage": "[rotate|revoke|show]",
   "aliases": [],
   "sources": []
  },
  {
   "name": "accesspanel",
   "category": "system",
   "brief": "Show the enforced access configuration.",
   "usage": "accesspanel",
   "aliases": [
    "config",
    "panel"
   ],
   "sources": []
  },
  {
   "name": "accessset",
   "category": "system",
   "brief": "Set one access field. Run `accesspanel` for the current values.",
   "usage": "<field> <value>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "apikeys",
   "category": "system",
   "brief": "Show which optional integrations are configured.",
   "usage": "apikeys",
   "aliases": [
    "keys"
   ],
   "sources": []
  },
  {
   "name": "approvals",
   "category": "system",
   "brief": "Show every approved user.",
   "usage": "approvals",
   "aliases": [
    "allowlist"
   ],
   "sources": []
  },
  {
   "name": "approve",
   "category": "system",
   "brief": "Authorise a Discord user to use the bot.",
   "usage": "<user id> [note]",
   "aliases": [],
   "sources": []
  },
  {
   "name": "audit",
   "category": "system",
   "brief": "Show recent audit entries from the database.",
   "usage": "[count]",
   "aliases": [],
   "sources": []
  },
  {
   "name": "botinvite",
   "category": "system",
   "brief": "Generate the OAuth2 invite URL for this bot.",
   "usage": "botinvite",
   "aliases": [],
   "sources": []
  },
  {
   "name": "commands",
   "category": "system",
   "brief": "Paginated index with one field per command.",
   "usage": "[category]",
   "aliases": [
    "cmds",
    "list"
   ],
   "sources": []
  },
  {
   "name": "help",
   "category": "system",
   "brief": "Show the command index or deep help for one command.",
   "usage": "[command]",
   "aliases": [
    "h"
   ],
   "sources": []
  },
  {
   "name": "maintenance",
   "category": "system",
   "brief": "Lock the instance to owners only.",
   "usage": "[on|off|status]",
   "aliases": [],
   "sources": []
  },
  {
   "name": "ping",
   "category": "system",
   "brief": "Latency, database and cache health.",
   "usage": "ping",
   "aliases": [],
   "sources": []
  },
  {
   "name": "reload",
   "category": "system",
   "brief": "Hot-reload one cog or every cog.",
   "usage": "<module>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "revoke",
   "category": "system",
   "brief": "Remove a user from the allow-list.",
   "usage": "<user id>",
   "aliases": [],
   "sources": []
  },
  {
   "name": "shutdown",
   "category": "system",
   "brief": "Stop the bot process.",
   "usage": "shutdown",
   "aliases": [],
   "sources": []
  },
  {
   "name": "sources",
   "category": "system",
   "brief": "List every upstream data source and its key requirement.",
   "usage": "sources",
   "aliases": [],
   "sources": []
  },
  {
   "name": "stats",
   "category": "system",
   "brief": "Instance-wide counters.",
   "usage": "stats",
   "aliases": [],
   "sources": []
  },
  {
   "name": "sync",
   "category": "system",
   "brief": "Force a slash-command sync.",
   "usage": "sync",
   "aliases": [],
   "sources": []
  },
  {
   "name": "whoami",
   "category": "system",
   "brief": "Show your access level and effective limits.",
   "usage": "whoami",
   "aliases": [
    "access"
   ],
   "sources": []
  }
 ],
 "total": 380,
 "routes": 626,
 "aliases": 246
};
