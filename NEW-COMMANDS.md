# New commands

These are the commands added after the 136-command release. Prefix commands are shown with `.`; `gen` is a group, so use `.gen <type>`.

## Generator commands (22)

All outputs are synthetic. Emails default to `example.com`, IPs use documentation ranges, phone numbers use fiction ranges, and generated secrets are not tied to any account.

| Command | What it creates | Arguments |
|---|---|---|
| `.gen address` | Generate a fictional postal address | — |
| `.gen apikey` | Generate a random test API token | — |
| `.gen color` | Generate a random hex colour | — |
| `.gen company` | Generate a fictional company name | — |
| `.gen domain` | Generate a reserved example domain | — |
| `.gen email` | Generate a synthetic email address | [domain] |
| `.gen handle` | Generate a synthetic social handle | — |
| `.gen ipv4` | Generate a documentation-range IPv4 address | — |
| `.gen ipv6` | Generate a documentation-range IPv6 address | — |
| `.gen isbn` | Generate a valid synthetic ISBN-13 | — |
| `.gen job` | Generate a fictional job title | — |
| `.gen lorem` | Generate a short placeholder sentence | — |
| `.gen mac` | Generate a locally administered MAC address | — |
| `.gen name` | Generate a fictional person's name | — |
| `.gen otp` | Generate a six-digit test code | — |
| `.gen passphrase` | Generate a hyphenated passphrase | [words] |
| `.gen password` | Generate a strong random password | [length] |
| `.gen phone` | Generate a reserved-range phone number | [region] |
| `.gen ulid` | Generate a ULID | — |
| `.gen useragent` | Return a realistic browser User-Agent string | — |
| `.gen username` | Generate a synthetic username | — |
| `.gen uuid` | Generate a random UUIDv4 | — |

## Toolkit commands (110)

Local-only utilities. No external request is made for these operations.

### Encoding, URLs and transforms (22)

| Command | What it does | Arguments |
|---|---|---|
| `.b64e` | Base64-encode a UTF-8 string. | <text> |
| `.b64d` | Decode a base64 string. | <text> |
| `.b32e` | Base32-encode a UTF-8 string. | <text> |
| `.b32d` | Decode a base32 string. | <text> |
| `.hexe` | Encode text as hexadecimal bytes. | <text> |
| `.hexd` | Decode hexadecimal bytes to text. | <hex> |
| `.urle` | Percent-encode text for a URL component. | <text> |
| `.urld` | Decode percent-encoded text. | <text> |
| `.rot13` | Apply the ROT13 substitution. | <text> |
| `.tobin` | Render UTF-8 bytes as binary. | <text> |
| `.frombin` | Decode binary bytes to UTF-8. | <bits> |
| `.morse` | Encode text as International Morse. | <text> |
| `.unmorse` | Decode International Morse. | <morse> |
| `.puny` | Convert a domain to its IDNA form. | <domain> |
| `.unpuny` | Decode an IDNA domain. | <domain> |
| `.codepoints` | Show the Unicode code point of each character. | <text> |
| `.fromcodepoints` | Build text from Unicode code points. | <points> |
| `.htmlenc` | Escape text for HTML. | <text> |
| `.htmlunesc` | Unescape HTML entities. | <text> |
| `.urlinspect` | Break a URL into scheme, host, path and query. | <url> |
| `.queryparse` | Parse a query string. | <query> |
| `.querybuild` | Encode key/value pairs as a query string. | <pairs> |

### Hashes and entropy (11)

| Command | What it does | Arguments |
|---|---|---|
| `.md5` | MD5 digest of a string. | <text> |
| `.sha1` | SHA-1 digest of a string. | <text> |
| `.sha256` | SHA-256 digest of a string. | <text> |
| `.sha512` | SHA-512 digest of a string. | <text> |
| `.blake2b` | BLAKE2b digest of a string. | <text> |
| `.sha3` | SHA3-256 digest of a string. | <text> |
| `.crc32` | CRC-32 checksum of a string. | <text> |
| `.hmacsha256` | HMAC-SHA256 of `key\|message`. | <key\|message> |
| `.hashident` | Identify a hash by length and prefix. | <hash> |
| `.entropy` | Measure Shannon entropy of text. | <text> |
| `.passwordbits` | Estimate password strength without storing it. | <password> |

### Text utilities (16)

| Command | What it does | Arguments |
|---|---|---|
| `.slug` | Convert text to a URL-safe slug. | <text> |
| `.uppercase` | Convert text to uppercase. | <text> |
| `.lowercase` | Convert text to lowercase. | <text> |
| `.titlecase` | Convert text to title case. | <text> |
| `.swapcase` | Swap the case of every character. | <text> |
| `.reverse` | Reverse a string. | <text> |
| `.wordcount` | Count words in text. | <text> |
| `.charcount` | Count characters and lines. | <text> |
| `.dedupe` | Remove duplicate lines while preserving order. | <text> |
| `.sortlines` | Sort lines alphabetically. | <text> |
| `.striphtml` | Remove HTML tags and decode entities. | <html> |
| `.linenums` | Add line numbers to text. | <text> |
| `.linewrap` | Wrap text at a chosen width: `width\|text`. | <width\|text> |
| `.difftext` | Unified diff between `left\|right`. | <left\|right> |
| `.textstats` | Count characters, words, lines and unique words. | <text> |
| `.bytecount` | Show UTF-8, base64 and hex sizes. | <text> |

### JSON, JWT and structured data (10)

| Command | What it does | Arguments |
|---|---|---|
| `.jsonfmt` | Pretty-print JSON. | <json> |
| `.jsonmin` | Minify JSON. | <json> |
| `.jsonkeys` | List every key path in JSON. | <json> |
| `.jsonvals` | Show top-level JSON values. | <json> |
| `.jsoncheck` | Validate JSON and report its type. | <json> |
| `.jwtinspect` | Decode JWT header and payload without verifying. | <token> |
| `.jwtpayload` | Show only a JWT payload. | <token> |
| `.jwtcheck` | Check JWT shape and algorithm. | <token> |
| `.csvjson` | Convert CSV with a header row to JSON. | <csv> |
| `.mime` | Look up a MIME type or extension. | <mime\|extension> |

### IP, CIDR and HTTP metadata (17)

| Command | What it does | Arguments |
|---|---|---|
| `.ip2int` | Convert IPv4 to its 32-bit integer. | <ipv4> |
| `.int2ip` | Convert a 32-bit integer to IPv4. | <integer> |
| `.ipv6expand` | Expand an IPv6 address. | <ipv6> |
| `.ipv6compress` | Compress an IPv6 address. | <ipv6> |
| `.ipclass` | Classify an address and its flags. | <ip> |
| `.ptrsuffix` | Build the reverse-DNS name for an address. | <ip> |
| `.macfmt` | Normalise a MAC address into three formats. | <mac> |
| `.cidrsplit` | Split a CIDR block: `cidr\|prefix`. | <cidr\|prefix> |
| `.cidrmerge` | Collapse overlapping CIDR blocks. | <cidrs> |
| `.ipv4range` | Describe an inclusive IPv4 range. | <first\|last> |
| `.ipv6range` | Describe an inclusive IPv6 range. | <first\|last> |
| `.cidrcontains` | Test whether an address is inside a block. | <cidr\|address> |
| `.wildcardmask` | Show the Cisco wildcard mask for IPv4. | <cidr> |
| `.portmap` | Map a port number to a common service, or search by name. | <port\|service> |
| `.protocol` | Map an IP protocol number to its name. | <number\|name> |
| `.statuscode` | Explain an HTTP status code. | <code> |
| `.httpmethod` | Describe an HTTP method. | <method> |

### Headers and parser helpers (4)

| Command | What it does | Arguments |
|---|---|---|
| `.csp` | List Content-Security-Policy directives. | <policy> |
| `.hsts` | Parse Strict-Transport-Security directives. | <header> |
| `.cookieparse` | Break a Set-Cookie value into pairs. | <cookie> |
| `.useragentparse` | Inspect a User-Agent string. | <user-agent> |

### Validation (7)

| Command | What it does | Arguments |
|---|---|---|
| `.uuidcheck` | Validate a UUID and report its variant. | <uuid> |
| `.isbncheck` | Validate an ISBN-10 or ISBN-13. | <isbn> |
| `.luhn` | Validate a number with the Luhn checksum. | <number> |
| `.base64check` | Check whether a string is valid base64. | <text> |
| `.domaincheck` | Validate a domain and show its registrable form. | <domain> |
| `.emailcheck` | Validate an email address structurally. | <email> |
| `.ipcheck` | Validate an IP address and show its flags. | <ip> |

### Numbers and math (15)

| Command | What it does | Arguments |
|---|---|---|
| `.baseconvert` | Convert a number between bases: `from\|to\|number`. | <from\|to\|number> |
| `.roman` | Convert an integer to a Roman numeral. | <1-3999> |
| `.unroman` | Convert a Roman numeral to an integer. | <numeral> |
| `.gcd` | Greatest common divisor of two or more numbers. | <a> <b> |
| `.lcm` | Least common multiple of two or more numbers. | <a> <b> |
| `.prime` | Test whether a number is prime. | <number> |
| `.factors` | List every factor of a number. | <number> |
| `.fib` | Print Fibonacci terms. | <count> |
| `.percent` | Calculate `part\|whole` as a percentage. | <part\|whole> |
| `.sortnums` | Sort numbers in ascending order. | <numbers> |
| `.sum` | Sum a list of numbers. | <numbers> |
| `.mean` | Arithmetic mean of a list of numbers. | <numbers> |
| `.median` | Median of a list of numbers. | <numbers> |
| `.mode` | Most common number in a list. | <numbers> |
| `.numrange` | Difference between the largest and smallest number. | <numbers> |

### Colours (4)

| Command | What it does | Arguments |
|---|---|---|
| `.hexrgb` | Convert a hex colour to RGB and HSL. | <#hex> |
| `.rgbhex` | Convert RGB channels to hex. | <r> <g> <b> |
| `.contrast` | Calculate WCAG contrast between two colours. | <#hex> <#hex> |
| `.randomcolor` | Generate one or more random hex colours. | [count] |

### Time and dates (4)

| Command | What it does | Arguments |
|---|---|---|
| `.unix` | Convert a Unix timestamp, or show the current time. | [timestamp] |
| `.unixdate` | Convert a date to a Unix timestamp. | <date> |
| `.weekday` | Show the weekday and ISO week for a date. | <date> |
| `.duration` | Format a number of seconds as days and clock time. | <seconds> |

## Examples

```text
.gen email
.gen password 32
.gen phone GB
.b64e hello world
.sha256 test
.jsonfmt {"ok":true}
.cidrsplit 10.0.0.0/24|26
.contrast #000000 #ffffff
```

The full command count is 360 top-level commands, or 379 catalogued operations counting every `gen` subcommand.

## Payload craft (100)

Every command below runs locally: no input is sent anywhere. The phishing group is
defensive — it explains a lure, fingerprints a kit and enumerates lookalikes for
registration, and never hosts, submits or sends anything.

### Lure analysis and lookalike defence (15)

| Command | What it does | Arguments |
|---|---|---|
| `.phishmask` | Show the gap between a link's label and its real destination. | `<url>` |
| `.phishlure` | Score a lure message for social-engineering markers. | `<message text>` |
| `.phishdork` | Hunt dorks for lookalike infrastructure impersonating a brand. | `<brand>` |
| `.phishkit` | Fingerprint a phishing kit from an HTML or source snippet. | `<html snippet>` |
| `.typosquat` | Enumerate lookalike domains for defensive registration. | `<domain>` |
| `.homoglyph` | Render text with Unicode confusables. | `<text>` |
| `.dehomoglyph` | Normalise lookalike characters back to ASCII. | `<text>` |
| `.confusable` | Detect mixed-script labels in a domain. | `<domain>` |
| `.urlentropy` | Measure host and path entropy for generated-looking URLs. | `<url>` |
| `.urlunwrap` | Unwrap nested encodings and redirect parameters offline. | `<url>` |
| `.redirparams` | List redirect-style query parameters and their targets. | `<url>` |
| `.defang` | Defang URLs and indicators for safe sharing. | `<text>` |
| `.refang` | Restore a defanged indicator. | `<text>` |
| `.iocs` | Extract indicators from pasted text. | `<text>` |
| `.httphdr` | Explain an HTTP header. | `<header>` |

### Ciphers, encodings and text forensics (40)

| Command | What it does | Arguments |
|---|---|---|
| `.caesar` | Shift letters with a Caesar rotation. | `<shift|text>` |
| `.uncaesar` | Print all 26 Caesar rotations. | `<text>` |
| `.rot47` | Apply the self-inverse ROT47 rotation. | `<text>` |
| `.atbash` | Apply the Atbash letter reversal. | `<text>` |
| `.a1z26` | Encode letters as 1–26 numbers. | `<text>` |
| `.una1z26` | Decode 1–26 numbers to letters. | `<numbers>` |
| `.vigenere` | Vigenère-encrypt with a keyword. | `<key|text>` |
| `.unvigenere` | Vigenère-decrypt with a keyword. | `<key|text>` |
| `.railfence` | Rail-fence encode with N rails. | `<rails|text>` |
| `.unrailfence` | Rail-fence decode with N rails. | `<rails|text>` |
| `.bacon` | Encode letters as Bacon's A/B groups. | `<text>` |
| `.unbacon` | Decode Bacon's A/B groups. | `<bits>` |
| `.base58` | Encode text as base58 (Bitcoin alphabet). | `<text>` |
| `.unbase58` | Decode base58 text. | `<text>` |
| `.base36` | Encode text as base36. | `<text>` |
| `.unbase36` | Decode base36 text. | `<text>` |
| `.base85` | Encode text as base85. | `<text>` |
| `.unbase85` | Decode base85 text. | `<text>` |
| `.b64url` | Encode text as URL-safe base64. | `<text>` |
| `.unb64url` | Decode URL-safe base64. | `<text>` |
| `.hexdump` | Show offset, hex and ASCII for any text. | `<text>` |
| `.fromhexdump` | Rebuild text from a hex dump. | `<dump>` |
| `.xorhex` | XOR text with a hex key. | `<keyhex|text>` |
| `.bitreverse` | Reverse the bit order of every byte. | `<text>` |
| `.unicodeescape` | Escape text as \uXXXX sequences. | `<text>` |
| `.ununicode` | Decode escape sequences. | `<escaped>` |
| `.zerowidth` | Reveal zero-width and invisible characters. | `<text>` |
| `.stripzero` | Remove zero-width characters. | `<text>` |
| `.leet` | Convert text to leetspeak. | `<text>` |
| `.unleet` | Approximate leetspeak decoding. | `<text>` |
| `.nato` | Spell text with the NATO alphabet. | `<text>` |
| `.unnato` | Decode NATO alphabet words. | `<words>` |
| `.freq` | Character frequency table. | `<text>` |
| `.ngrams` | Top bigrams and trigrams. | `<text>` |
| `.wordfreq` | Most common words with counts. | `<text>` |
| `.acrostic` | Read the first letter of every line. | `<text>` |
| `.palindrome` | Test whether text is a palindrome. | `<text>` |
| `.anagram` | Compare two strings as anagrams. | `<left|right>` |
| `.readability` | Flesch reading ease and grade level. | `<text>` |
| `.passwordpolicy` | Evaluate a password against policy rules. | `<password>` |

### Hashes, keys and local utilities (20)

| Command | What it does | Arguments |
|---|---|---|
| `.adler32` | Adler-32 checksum. | `<text>` |
| `.fnv1a` | FNV-1a 32- and 64-bit hashes. | `<text>` |
| `.murmur3` | MurmurHash3 x86 32-bit — the favicon pivot hash. | `<text>` |
| `.hmacmd5` | HMAC-MD5 of `key|message`. | `<key|message>` |
| `.hmacsha1` | HMAC-SHA1 of `key|message`. | `<key|message>` |
| `.hmacsha512` | HMAC-SHA512 of `key|message`. | `<key|message>` |
| `.pbkdf2` | Derive a key with PBKDF2-HMAC-SHA256. | `<salt|password>` |
| `.hashmode` | Suggest hashcat modes for a hash. | `<hash>` |
| `.johnmode` | Suggest a John the Ripper format for a hash. | `<hash>` |
| `.crondesc` | Explain a cron expression. | `<expression>` |
| `.semver` | Validate and decompose a semantic version. | `<version>` |
| `.regexplain` | Explain the constructs in a regular expression. | `<pattern>` |
| `.csvtable` | Convert CSV into a Markdown table. | `<csv>` |
| `.colorblind` | Simulate a hex colour under colour-vision deficiencies. | `<#hex>` |
| `.ts` | Parse a timestamp into every useful format. | `<timestamp>` |
| `.offsettime` | Show one instant across time zones. | `<timestamp>` |
| `.httpdate` | Parse an HTTP date header. | `<date>` |
| `.caseconv` | Convert between naming styles. | `<style|text>` |
| `.jsonflat` | Flatten JSON into dotted paths. | `<json>` |
| `.epochtime` | Convert epoch seconds, millis or a date. | `<value>` |

### Network-local parsers (9)

| Command | What it does | Arguments |
|---|---|---|
| `.subnetinfo` | Full breakdown of a CIDR block. | `<cidr>` |
| `.supernet` | Summarise a block into a parent prefix. | `<cidr|prefix>` |
| `.ipv6type` | Classify an IPv6 address (ULA, link-local, 6to4, Teredo). | `<ipv6>` |
| `.portrange` | Expand a port list or range. | `<80,443,8000-8100>` |
| `.tcpflags` | Decode a TCP flag byte or flag names. | `<0x12|SYN,ACK>` |
| `.icmpcode` | Explain an ICMP type and code. | `<type|code>` |
| `.dnstype` | Explain a DNS record type. | `<type>` |
| `.ciphersuite` | Decompose a TLS cipher suite name. | `<suite>` |
| `.rangeexpand` | Expand an IPv4 range into addresses. | `<first|last>` |

### Mail and name parsers (3)

| Command | What it does | Arguments |
|---|---|---|
| `.authresults` | Parse an Authentication-Results header. | `<header value>` |
| `.received` | Parse a Received header chain. | `<headers>` |
| `.idnlabels` | Break a domain into ASCII and Unicode labels. | `<domain>` |

### Discord-local helpers (6)

| Command | What it does | Arguments |
|---|---|---|
| `.fakesnowflake` | Build a Discord snowflake for a timestamp. | `[date]` |
| `.tokentype` | Classify a token's shape without echoing it. | `<token>` |
| `.snowflakerange` | Snowflake bounds for one UTC day. | `<date>` |
| `.perms` | Decode a Discord permission bitfield. | `<integer>` |
| `.intents` | Decode a gateway intents bitfield. | `<integer>` |
| `.oauthscopes` | Explain Discord OAuth2 scopes. | `[scope]` |

### Synthetic generators (7)

| Command | What it does | Arguments |
|---|---|---|
| `.fakecard` | Generate a Luhn-valid synthetic card number. | `[bin prefix]` |
| `.fakeiban` | Generate a MOD-97-valid synthetic IBAN. | `[country]` |
| `.fakeimei` | Generate a Luhn-valid synthetic IMEI. | `[tac]` |
| `.fakehash` | Generate a hex hash of a chosen length. | `[length]` |
| `.fakejwt` | Build an unsigned demo JWT. | `[subject]` |
| `.uuid7` | Generate a time-ordered UUIDv7. | `[date]` |
| `.nanoid` | Generate a URL-safe random identifier. | `[length]` |

## Watchtower (8)

| Command | What it does | Arguments |
|---|---|---|
| `.vanitycheck` | Resolve an invite code, path or full link: state, server, members, features, risk. | `<code\|link>` |
| `.vanitysnipe` | Availability report plus a manual claim checklist for a vanity. | `<code\|link>` |
| `.vanitywatch` | Watch up to eight codes in one command; one notice per transition. | `<code…>` |
| `.usernamecheck` | Check one handle across seven public surfaces, with a score line. | `<username>` |
| `.usernamesnipe` | Release plan and fallback names for a handle; no automation. | `<username>` |
| `.sniperlist` | List active watches with poll counts and age. | — |
| `.sniperstop` | Stop one watch, or all of them. | `<target\|all>` |

`.vanitywatch` also answers to `vbatch` and `vanityscan`. Invite validation accepts
`discord.gg/code`, `discord.com/invite/code`, a bare path and the `?event=` form;
resolution is cached for 30 seconds so a batch check does not hammer the endpoint.

The poll interval comes from the stored configuration (`watch_interval`, default
60s, floor 30s) and the number of simultaneous watches is capped by `max_watches`.
Both are editable from the access console or with `.accessset`. Watches are
session-scoped: restarting the bot clears them.

## Access console (owner only)

| Command | What it does | Arguments |
|---|---|---|
| `.accesspanel` | Show the enforced configuration, key fingerprint and warnings. | — |
| `.accesskey` | Issue, rotate, revoke or fingerprint the console pairing key. | `[show\|rotate\|revoke]` |
| `.accessset` | Set one field, e.g. `approval_required false`. | `<field> <value>` |
| `.accessexport` | Export the configuration as one pasteable block for `site/access.html`. | — |
| `.accessimport` | Apply a block produced by the website console. | `<export>` |
| `.accessfields` | List every field, its current value and its purpose. | — |

`.accesspanel` also answers to `config` and `panel`. Fields are normalised on write:
booleans accept `true/false/on/off`, numbers are clamped to their documented range,
and the maintenance flag plus the watch interval are mirrored to the keys the rest
of the bot already reads. No restart is needed after an import.
