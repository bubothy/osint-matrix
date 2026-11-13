"""Signature tables.

These are deliberately data-only: technology fingerprints, WAF markers, CDN
CNAME suffixes, disposable mail providers, hash formats, username enumeration
targets, DNS blocklists, IBAN lengths, security header weights and search
dork templates.
"""

from __future__ import annotations

from typing import Any

# ── technology fingerprints ────────────────────────────────────────────────
# headers: header name -> regex the value must match ("" = presence is enough)
# cookies: cookie names that imply the technology
# html:    regexes searched in the document body

TECH_SIGNATURES: list[dict[str, Any]] = [
    {"name": "Cloudflare", "category": "CDN / WAF", "headers": {"cf-ray": "", "server": r"(?i)cloudflare"}, "cookies": ["__cf_bm", "cf_clearance", "__cflb"]},
    {"name": "Cloudflare Workers", "category": "Edge runtime", "headers": {"server": r"(?i)cloudflare", "cf-worker": ""}, "html": []},
    {"name": "Akamai", "category": "CDN", "headers": {"x-akamai-transformed": "", "server": r"(?i)AkamaiGHost", "x-akamai-request-id": ""}, "html": []},
    {"name": "Fastly", "category": "CDN", "headers": {"x-fastly-request-id": "", "x-served-by": r"(?i)cache-", "fastly-debug-digest": ""}, "html": []},
    {"name": "Amazon CloudFront", "category": "CDN", "headers": {"x-amz-cf-id": "", "via": r"(?i)cloudfront"}, "html": []},
    {"name": "Amazon S3", "category": "Object storage", "headers": {"server": r"(?i)AmazonS3"}, "html": [r"(?i)<ListBucketResult"]},
    {"name": "AWS ALB", "category": "Load balancer", "headers": {"server": r"(?i)awselb", "x-amzn-requestid": ""}, "html": []},
    {"name": "Vercel", "category": "Hosting", "headers": {"server": r"(?i)vercel", "x-vercel-id": "", "x-vercel-cache": ""}, "html": [r"(?i)_next/static"]},
    {"name": "Netlify", "category": "Hosting", "headers": {"server": r"(?i)Netlify", "x-nf-request-id": ""}, "html": []},
    {"name": "GitHub Pages", "category": "Hosting", "headers": {"server": r"(?i)GitHub\.com", "x-github-request-id": ""}, "html": []},
    {"name": "Azure Front Door", "category": "CDN", "headers": {"x-azure-ref": ""}, "html": []},
    {"name": "Azure App Service", "category": "Hosting", "headers": {"x-ms-request-id": "", "server": r"(?i)Microsoft-IIS"}, "html": []},
    {"name": "Google Cloud", "category": "Hosting", "headers": {"server": r"(?i)gws|Google Frontend", "x-cloud-trace-context": ""}, "html": []},
    {"name": "Bunny CDN", "category": "CDN", "headers": {"server": r"(?i)BunnyCDN", "cdn-requestid": ""}, "html": []},
    {"name": "nginx", "category": "Web server", "headers": {"server": r"(?i)nginx"}, "html": []},
    {"name": "Apache httpd", "category": "Web server", "headers": {"server": r"(?i)Apache(?:/|$)"}, "html": []},
    {"name": "LiteSpeed", "category": "Web server", "headers": {"server": r"(?i)LiteSpeed"}, "html": []},
    {"name": "Microsoft IIS", "category": "Web server", "headers": {"server": r"(?i)Microsoft-IIS"}, "html": []},
    {"name": "Caddy", "category": "Web server", "headers": {"server": r"(?i)Caddy"}, "html": []},
    {"name": "OpenResty", "category": "Web server", "headers": {"server": r"(?i)openresty"}, "html": []},
    {"name": "Envoy", "category": "Proxy", "headers": {"server": r"(?i)envoy", "x-envoy-upstream-service-time": ""}, "html": []},
    {"name": "Traefik", "category": "Proxy", "headers": {"server": r"(?i)traefik"}, "html": []},
    {"name": "HAProxy", "category": "Load balancer", "headers": {"server": r"(?i)haproxy"}, "html": []},
    {"name": "Next.js", "category": "Framework", "headers": {"x-nextjs-cache": "", "x-nextjs-prerender": ""}, "html": [r"__NEXT_DATA__", r"/_next/static/"]},
    {"name": "Nuxt", "category": "Framework", "headers": {}, "html": [r"__NUXT__", r"/_nuxt/"]},
    {"name": "Gatsby", "category": "Framework", "headers": {}, "html": [r"(?i)gatsby-", r"/page-data/"]},
    {"name": "React", "category": "JavaScript library", "headers": {}, "html": [r"data-reactroot", r"react\.production", r"__REACT_DEVTOOLS"]},
    {"name": "Vue.js", "category": "JavaScript library", "headers": {}, "html": [r"data-v-[0-9a-f]{8}", r"vue(?:\.min)?\.js"]},
    {"name": "Angular", "category": "Framework", "headers": {}, "html": [r"ng-version=", r"ng-app="]},
    {"name": "Svelte", "category": "Framework", "headers": {}, "html": [r"svelte-[a-z0-9]{6}", r"__sveltekit"]},
    {"name": "Astro", "category": "Framework", "headers": {}, "html": [r"astro-island", r"/_astro/"]},
    {"name": "Remix", "category": "Framework", "headers": {"x-remix": ""}, "html": [r"__remixContext"]},
    {"name": "jQuery", "category": "JavaScript library", "headers": {}, "html": [r"jquery(?:-[\d.]+)?(?:\.min)?\.js"]},
    {"name": "Bootstrap", "category": "CSS framework", "headers": {}, "html": [r"bootstrap(?:\.min)?\.css"]},
    {"name": "Tailwind CSS", "category": "CSS framework", "headers": {}, "html": [r"(?i)tailwind"]},
    {"name": "WordPress", "category": "CMS", "headers": {"x-powered-by": r"(?i)WordPress", "link": r"(?i)wp-json"}, "html": [r"/wp-content/", r"/wp-includes/", r'name="generator" content="WordPress']},
    {"name": "WooCommerce", "category": "E-commerce", "headers": {}, "html": [r"/wp-content/plugins/woocommerce/"]},
    {"name": "Drupal", "category": "CMS", "headers": {"x-generator": r"(?i)Drupal"}, "html": [r"(?i)Drupal\.settings", r"sites/default/files"]},
    {"name": "Joomla", "category": "CMS", "headers": {}, "html": [r"/media/jui/", r'content="Joomla!']},
    {"name": "Magento", "category": "E-commerce", "headers": {"x-magento-cache-debug": ""}, "html": [r"/static/version\d+/", r"Magento_"]},
    {"name": "Shopify", "category": "E-commerce", "headers": {"x-shopid": "", "x-shardid": ""}, "html": [r"cdn\.shopify\.com", r"Shopify\.theme"]},
    {"name": "Wix", "category": "Site builder", "headers": {"x-wix-request-id": ""}, "html": [r"parastorage\.com", r"wix\.com"]},
    {"name": "Squarespace", "category": "Site builder", "headers": {"server": r"(?i)Squarespace"}, "html": [r"static1\.squarespace\.com"]},
    {"name": "Webflow", "category": "Site builder", "headers": {"x-wf-page-id": ""}, "html": [r"assets\.website-files\.com"]},
    {"name": "Ghost", "category": "CMS", "headers": {}, "html": [r'content="Ghost', r"ghost-sdk"]},
    {"name": "Discourse", "category": "Forum", "headers": {"x-discourse-route": ""}, "html": [r"discourse-cooked"]},
    {"name": "Moodle", "category": "LMS", "headers": {}, "html": [r"(?i)moodle", r"/theme/yui_combo"]},
    {"name": "phpBB", "category": "Forum", "headers": {}, "html": [r"(?i)phpBB"]},
    {"name": "PHP", "category": "Language", "headers": {"x-powered-by": r"(?i)PHP"}, "cookies": ["PHPSESSID"], "html": []},
    {"name": "ASP.NET", "category": "Framework", "headers": {"x-aspnet-version": "", "x-powered-by": r"(?i)ASP\.NET"}, "cookies": ["ASP.NET_SessionId", ".AspNetCore.Session"], "html": []},
    {"name": "Django", "category": "Framework", "headers": {}, "cookies": ["csrftoken", "django_language"], "html": [r"csrfmiddlewaretoken"]},
    {"name": "Ruby on Rails", "category": "Framework", "headers": {"x-runtime": "", "x-rack-cache": ""}, "cookies": ["_rails_session"], "html": []},
    {"name": "Laravel", "category": "Framework", "headers": {}, "cookies": ["laravel_session", "XSRF-TOKEN"], "html": []},
    {"name": "Express", "category": "Framework", "headers": {"x-powered-by": r"(?i)Express"}, "html": []},
    {"name": "Spring Boot", "category": "Framework", "headers": {"x-application-context": ""}, "html": [r"Whitelabel Error Page"]},
    {"name": "GraphQL", "category": "API", "headers": {}, "html": [r"(?i)graphql", r"/graphql"]},
    {"name": "Google Analytics", "category": "Analytics", "headers": {}, "html": [r"google-analytics\.com/(?:ga|analytics)\.js", r"googletagmanager\.com/gtag/js"]},
    {"name": "Google Tag Manager", "category": "Tag manager", "headers": {}, "html": [r"googletagmanager\.com/gtm\.js"]},
    {"name": "Meta Pixel", "category": "Analytics", "headers": {}, "html": [r"connect\.facebook\.net/.*/fbevents\.js"]},
    {"name": "Hotjar", "category": "Analytics", "headers": {}, "html": [r"static\.hotjar\.com"]},
    {"name": "Sentry", "category": "Monitoring", "headers": {}, "html": [r"sentry\.io", r"@sentry/browser"]},
    {"name": "New Relic", "category": "Monitoring", "headers": {}, "html": [r"js-agent\.newrelic\.com"]},
    {"name": "reCAPTCHA", "category": "Bot defence", "headers": {}, "html": [r"google\.com/recaptcha", r"gstatic\.com/recaptcha"]},
    {"name": "hCaptcha", "category": "Bot defence", "headers": {}, "html": [r"hcaptcha\.com"]},
    {"name": "Stripe", "category": "Payments", "headers": {}, "html": [r"js\.stripe\.com"]},
    {"name": "PayPal", "category": "Payments", "headers": {}, "html": [r"paypal\.com/sdk/js", r"paypalobjects\.com"]},
    {"name": "Intercom", "category": "Support", "headers": {}, "html": [r"widget\.intercom\.io"]},
    {"name": "Zendesk", "category": "Support", "headers": {}, "html": [r"static\.zdassets\.com", r"zendesk\.com"]},
    {"name": "Crisp", "category": "Support", "headers": {}, "html": [r"client\.crisp\.chat"]},
    {"name": "Algolia", "category": "Search", "headers": {}, "html": [r"algolia(?:net|\.js)"]},
    {"name": "Auth0", "category": "Identity", "headers": {}, "html": [r"cdn\.auth0\.com"]},
    {"name": "Okta", "category": "Identity", "headers": {}, "html": [r"okta\.com", r"oktacdn\.com"]},
]

# ── WAF / edge markers ─────────────────────────────────────────────────────

WAF_SIGNATURES: list[dict[str, Any]] = [
    {"name": "Cloudflare", "headers": ["cf-ray", "cf-cache-status", "cf-request-id"], "cookies": ["__cf_bm", "cf_clearance"]},
    {"name": "Akamai", "headers": ["x-akamai-request-id", "x-akamai-transformed"], "cookies": ["ak_bmsc", "bm_sv"]},
    {"name": "Imperva / Incapsula", "headers": ["x-iinfo", "x-cdn"], "cookies": ["visid_incap", "incap_ses"]},
    {"name": "F5 BIG-IP ASM", "headers": ["x-wa-info"], "cookies": ["BIGipServer", "TS01"]},
    {"name": "Sucuri", "headers": ["x-sucuri-id", "x-sucuri-cache"], "cookies": []},
    {"name": "AWS WAF", "headers": ["x-amzn-requestid"], "cookies": ["aws-waf-token"]},
    {"name": "Fastly", "headers": ["x-fastly-request-id"], "cookies": []},
    {"name": "Azure Front Door", "headers": ["x-azure-ref"], "cookies": []},
    {"name": "Barracuda", "headers": [], "cookies": ["barra_counter_session", "BNI_persistence"]},
    {"name": "Fortinet FortiWeb", "headers": [], "cookies": ["FORTIWAFSID"]},
    {"name": "Wallarm", "headers": ["x-wallarm-waf-check"], "cookies": []},
    {"name": "Radware", "headers": [], "cookies": ["rdwr"]},
    {"name": "DenyAll", "headers": [], "cookies": ["sessioncookie"]},
    {"name": "Vercel Edge", "headers": ["x-vercel-id"], "cookies": []},
    {"name": "Netlify Edge", "headers": ["x-nf-request-id"], "cookies": []},
    {"name": "ModSecurity", "headers": ["x-mod-security"], "cookies": []},
]

# ── CDN CNAME suffixes ─────────────────────────────────────────────────────

CDN_CNAME: list[tuple[str, str]] = [
    ("cloudfront.net", "Amazon CloudFront"),
    ("akamaiedge.net", "Akamai"),
    ("akamai.net", "Akamai"),
    ("edgekey.net", "Akamai"),
    ("edgesuite.net", "Akamai"),
    ("fastly.net", "Fastly"),
    ("fastlylb.net", "Fastly"),
    ("cloudflare.net", "Cloudflare"),
    ("cloudflare.com", "Cloudflare"),
    ("azureedge.net", "Azure CDN"),
    ("trafficmanager.net", "Azure Traffic Manager"),
    ("azurefd.net", "Azure Front Door"),
    ("cdn77.org", "CDN77"),
    ("bunnycdn.com", "Bunny CDN"),
    ("stackpathdns.com", "StackPath"),
    ("netlify.app", "Netlify"),
    ("netlify.com", "Netlify"),
    ("vercel.app", "Vercel"),
    ("now.sh", "Vercel"),
    ("herokuapp.com", "Heroku"),
    ("github.io", "GitHub Pages"),
    ("firebaseapp.com", "Firebase Hosting"),
    ("web.app", "Firebase Hosting"),
    ("azurewebsites.net", "Azure App Service"),
    ("googlehosted.com", "Google"),
    ("wpengine.com", "WP Engine"),
    ("pantheonsite.io", "Pantheon"),
    ("kinstacdn.com", "Kinsta"),
    ("rsc.cdn77.org", "CDN77"),
    ("impervadns.net", "Imperva"),
    ("sucuridns.com", "Sucuri"),
    ("incapdns.net", "Imperva"),
]

# ── email intelligence ─────────────────────────────────────────────────────

DISPOSABLE_DOMAINS = {
    "10minutemail.com", "10minutemail.net", "20minutemail.com", "33mail.com", "anonbox.net",
    "burnermail.io", "byom.de", "cock.li", "discard.email", "discardmail.com", "dispostable.com",
    "dropmail.me", "emailondeck.com", "fakeinbox.com", "fakemail.net", "getairmail.com",
    "getnada.com", "guerrillamail.com", "guerrillamail.net", "guerrillamail.org", "harakirimail.com",
    "inboxkitten.com", "jetable.org", "linshiyouxiang.net", "mailcatch.com", "maildrop.cc",
    "mailinator.com", "mailnesia.com", "mailnull.com", "mailsac.com", "mailtemp.info",
    "mintemail.com", "moakt.com", "mohmal.com", "mytemp.email", "nada.email", "sharklasers.com",
    "spam4.me", "spambog.com", "spamgourmet.com", "temp-mail.io", "temp-mail.org", "tempmail.com",
    "tempmail.net", "tempr.email", "throwawaymail.com", "trashmail.com", "trashmail.de",
    "wegwerfemail.de", "yopmail.com", "yopmail.fr", "zetmail.com",
}

# ── hash formats ───────────────────────────────────────────────────────────

HASH_PATTERNS: list[tuple[str, str, str]] = [
    (r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$", "bcrypt", "Blowfish crypt — cost factor is the two digits"),
    (r"^\$argon2(?:id|i|d)\$", "Argon2", "Memory-hard KDF; parameters follow the prefix"),
    (r"^\$scrypt\$", "scrypt", "Memory-hard KDF"),
    (r"^\$pbkdf2-sha256\$", "PBKDF2-SHA256", "Iterated HMAC-SHA256"),
    (r"^\$7\$", "scrypt (crypt)", "Passlib scrypt format"),
    (r"^\$6\$", "SHA-512 crypt", "Linux /etc/shadow format"),
    (r"^\$5\$", "SHA-256 crypt", "Linux /etc/shadow format"),
    (r"^\$y\$", "yescrypt", "Modern Linux crypt format"),
    (r"^\$gy\$", "gost-yescrypt", "GOST + yescrypt"),
    (r"^\$1\$", "MD5 crypt", "Legacy Unix crypt"),
    (r"^\$apr1\$", "Apache APR1-MD5", "Apache htpasswd format"),
    (r"^\$P\$", "phpass", "WordPress < 6.8 / phpBB hashes"),
    (r"^\{SSHA\}", "LDAP SSHA", "Salted SHA-1, base64 payload"),
    (r"^\{SHA\}", "LDAP SHA", "Unsalted SHA-1, base64 payload"),
    (r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", "JSON Web Token", "header.payload.signature"),
    (r"^[a-fA-F0-9]{8}$", "CRC-32 / FNV-1a-32", "32-bit checksum, not a password hash"),
    (r"^[a-fA-F0-9]{16}$", "CRC-64 / FNV-1a-64", "64-bit checksum"),
    (r"^[a-fA-F0-9]{32}$", "MD5 / NTLM / MD4", "128-bit — indistinguishable without context"),
    (r"^[a-fA-F0-9]{40}$", "SHA-1 / MySQL5 / RIPEMD-160", "160-bit"),
    (r"^[a-fA-F0-9]{56}$", "SHA-224 / SHA3-224", "224-bit"),
    (r"^[a-fA-F0-9]{64}$", "SHA-256 / SHA3-256 / BLAKE2s", "256-bit"),
    (r"^[a-fA-F0-9]{96}$", "SHA-384 / SHA3-384", "384-bit"),
    (r"^[a-fA-F0-9]{128}$", "SHA-512 / SHA3-512 / BLAKE2b", "512-bit"),
    (r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", "UUID", "RFC 4122 identifier"),
    (r"^[A-Za-z0-9+/]{21}[AQgw]==$", "Base64 (16 bytes)", "Encoded 128-bit value"),
    (r"^[A-Za-z0-9+/]{43}=$", "Base64 (32 bytes)", "Encoded 256-bit value"),
]

# ── username enumeration targets ───────────────────────────────────────────
# reliable=False means the site answers 200 for missing accounts, so a hit
# cannot be confirmed mechanically.

USERNAME_SITES: list[dict[str, Any]] = [
    {"name": "GitHub", "url": "https://github.com/{u}", "category": "code", "reliable": True},
    {"name": "GitLab", "url": "https://gitlab.com/{u}", "category": "code", "reliable": True},
    {"name": "Codeberg", "url": "https://codeberg.org/{u}", "category": "code", "reliable": True},
    {"name": "Bitbucket", "url": "https://bitbucket.org/{u}", "category": "code", "reliable": True},
    {"name": "SourceForge", "url": "https://sourceforge.net/u/{u}/", "category": "code", "reliable": True},
    {"name": "Launchpad", "url": "https://launchpad.net/~{u}", "category": "code", "reliable": True},
    {"name": "Hugging Face", "url": "https://huggingface.co/{u}", "category": "code", "reliable": True},
    {"name": "Replit", "url": "https://replit.com/@{u}", "category": "code", "reliable": False},
    {"name": "Keybase", "url": "https://keybase.io/{u}", "category": "identity", "reliable": True},
    {"name": "Hacker News", "url": "https://news.ycombinator.com/user?id={u}", "category": "community", "reliable": True},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{u}", "category": "community", "reliable": True},
    {"name": "Dev.to", "url": "https://dev.to/{u}", "category": "community", "reliable": True},
    {"name": "Medium", "url": "https://medium.com/@{u}", "category": "writing", "reliable": False},
    {"name": "Substack", "url": "https://{u}.substack.com", "category": "writing", "reliable": True},
    {"name": "npm", "url": "https://www.npmjs.com/~{u}", "category": "packages", "reliable": True},
    {"name": "Docker Hub", "url": "https://hub.docker.com/u/{u}", "category": "packages", "reliable": True},
    {"name": "Kaggle", "url": "https://www.kaggle.com/{u}", "category": "data", "reliable": True},
    {"name": "Stack Overflow", "url": "https://stackoverflow.com/users/{u}", "category": "community", "reliable": False},
    {"name": "Telegram", "url": "https://t.me/{u}", "category": "messaging", "reliable": True},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{u}", "category": "gaming", "reliable": True},
    {"name": "Roblox", "url": "https://www.roblox.com/users/profile?username={u}", "category": "gaming", "reliable": False},
    {"name": "Twitch", "url": "https://www.twitch.tv/{u}", "category": "streaming", "reliable": False},
    {"name": "YouTube", "url": "https://www.youtube.com/@{u}", "category": "video", "reliable": True},
    {"name": "Vimeo", "url": "https://vimeo.com/{u}", "category": "video", "reliable": True},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{u}", "category": "audio", "reliable": True},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{u}", "category": "audio", "reliable": False},
    {"name": "Last.fm", "url": "https://www.last.fm/user/{u}", "category": "audio", "reliable": True},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{u}/", "category": "social", "reliable": False},
    {"name": "Flickr", "url": "https://www.flickr.com/people/{u}", "category": "photo", "reliable": True},
    {"name": "Behance", "url": "https://www.behance.net/{u}", "category": "design", "reliable": True},
    {"name": "Dribbble", "url": "https://dribbble.com/{u}", "category": "design", "reliable": True},
    {"name": "CodePen", "url": "https://codepen.io/{u}", "category": "design", "reliable": True},
    {"name": "JSFiddle", "url": "https://jsfiddle.net/user/{u}/", "category": "design", "reliable": True},
    {"name": "Goodreads", "url": "https://www.goodreads.com/{u}", "category": "books", "reliable": True},
    {"name": "Letterboxd", "url": "https://letterboxd.com/{u}/", "category": "film", "reliable": True},
    {"name": "Chess.com", "url": "https://www.chess.com/member/{u}", "category": "games", "reliable": True},
    {"name": "Duolingo", "url": "https://www.duolingo.com/profile/{u}", "category": "learning", "reliable": False},
    {"name": "Scratch", "url": "https://scratch.mit.edu/users/{u}/", "category": "learning", "reliable": True},
    {"name": "About.me", "url": "https://about.me/{u}", "category": "identity", "reliable": True},
    {"name": "Bluesky", "url": "https://bsky.app/profile/{u}.bsky.social", "category": "social", "reliable": False},
    {"name": "Mastodon (social)", "url": "https://mastodon.social/@{u}", "category": "social", "reliable": False},
    {"name": "X / Twitter", "url": "https://x.com/{u}", "category": "social", "reliable": False},
    {"name": "Instagram", "url": "https://www.instagram.com/{u}/", "category": "social", "reliable": False},
    {"name": "Facebook", "url": "https://www.facebook.com/{u}", "category": "social", "reliable": False},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{u}", "category": "social", "reliable": False},
]

# ── DNS blocklists ─────────────────────────────────────────────────────────

DNSBL_ZONES: list[tuple[str, str, str]] = [
    ("zen.spamhaus.org", "Spamhaus ZEN", "Combined SBL+XBL+PBL"),
    ("bl.spamcop.net", "SpamCop", "Reported spam sources"),
    ("b.barracudacentral.org", "Barracuda", "Reputation blocklist"),
    ("dnsbl.sorbs.net", "SORBS", "Aggregated open relays / proxies"),
    ("spam.dnsbl.sorbs.net", "SORBS Spam", "Direct spam sources"),
    ("dnsbl-1.uceprotect.net", "UCEPROTECT L1", "Single-IP spam sources"),
    ("dnsbl-2.uceprotect.net", "UCEPROTECT L2", "Netblock-level listings"),
    ("psbl.surriel.com", "PSBL", "Passive spam blocklist"),
    ("all.s5h.net", "s5h.net", "Aggregated sources"),
    ("hostkarma.junkemailfilter.com", "HostKarma", "Junk email filter reputation"),
    ("ix.dnsbl.manitu.net", "Manitu", "German spam blocklist"),
    ("cbl.abuseat.org", "CBL", "Composite blocking list"),
    ("db.wpbl.info", "WPBL", "Weighted private blocklist"),
    ("truncate.gbudb.net", "GBUdb", "Truncate reputation"),
]

# ── IBAN ───────────────────────────────────────────────────────────────────

IBAN_LENGTHS = {
    "AL": 28, "AD": 24, "AT": 20, "AZ": 28, "BH": 22, "BY": 28, "BE": 16, "BA": 20,
    "BR": 29, "BG": 22, "CR": 22, "HR": 21, "CY": 28, "CZ": 24, "DK": 18, "DO": 28,
    "EG": 29, "SV": 28, "EE": 20, "FO": 18, "FI": 18, "FR": 27, "GE": 22, "DE": 22,
    "GI": 23, "GR": 27, "GL": 18, "GT": 28, "HU": 28, "IS": 26, "IQ": 23, "IE": 22,
    "IL": 23, "IT": 27, "JO": 30, "KZ": 20, "XK": 20, "KW": 30, "LV": 21, "LB": 28,
    "LI": 21, "LT": 20, "LU": 20, "MK": 19, "MT": 31, "MR": 27, "MU": 30, "MD": 24,
    "MC": 27, "ME": 22, "NL": 18, "NO": 15, "PK": 24, "PS": 29, "PL": 28, "PT": 25,
    "QA": 29, "RO": 24, "LC": 32, "SM": 27, "ST": 25, "SA": 24, "RS": 22, "SC": 31,
    "SK": 24, "SI": 19, "ES": 24, "SE": 24, "CH": 21, "TL": 23, "TN": 24, "TR": 26,
    "UA": 29, "AE": 23, "GB": 22, "VA": 22, "VG": 24,
}

# ── user-agent parsing ─────────────────────────────────────────────────────

UA_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "browser": [
        ("Edge", r"Edg(?:e|A|iOS)?/([\d.]+)"),
        ("Opera", r"(?:OPR|Opera)[/ ]?([\d.]+)"),
        ("Samsung Internet", r"SamsungBrowser/([\d.]+)"),
        ("Vivaldi", r"Vivaldi/([\d.]+)"),
        ("Brave", r"Brave/([\d.]+)"),
        ("Firefox", r"Firefox/([\d.]+)"),
        ("Chrome", r"Chrome/([\d.]+)"),
        ("Safari", r"Version/([\d.]+).*Safari"),
        ("Internet Explorer", r"(?:MSIE |Trident/.*rv:)([\d.]+)"),
    ],
    "engine": [
        ("Blink", r"Chrome/"),
        ("Gecko", r"Gecko/"),
        ("WebKit", r"AppleWebKit/"),
        ("Presto", r"Presto/"),
    ],
    "os": [
        ("Windows 10/11", r"Windows NT 10\.0"),
        ("Windows 8.1", r"Windows NT 6\.3"),
        ("Windows 8", r"Windows NT 6\.2"),
        ("Windows 7", r"Windows NT 6\.1"),
        ("Windows", r"Windows NT ([\d.]+)"),
        ("Android", r"Android ([\d.]+)"),
        ("iOS", r"(?:iPhone|iPad|iPod).*?OS ([\d_]+)"),
        ("macOS", r"Mac OS X ([\d_.]+)"),
        ("Chrome OS", r"CrOS"),
        ("Ubuntu", r"Ubuntu"),
        ("Linux", r"Linux"),
    ],
    "device": [
        ("Tablet", r"iPad|Tablet|PlayBook|Silk"),
        ("Mobile", r"Mobile|iPhone|Android.*Mobile|Windows Phone"),
        ("Desktop", r"Windows NT|Macintosh|X11"),
        ("Bot / script", r"(?i)bot|crawler|spider|curl|wget|python|go-http|axios|node-fetch|requests"),
    ],
}

# ── HTTP security posture ──────────────────────────────────────────────────

SECURITY_HEADERS: list[dict[str, Any]] = [
    {
        "header": "strict-transport-security",
        "label": "HSTS",
        "weight": 3,
        "expect": "max-age >= 15552000; includeSubDomains; preload",
        "why": "Pins future visits to HTTPS, blocking SSL-strip downgrade attacks.",
    },
    {
        "header": "content-security-policy",
        "label": "CSP",
        "weight": 3,
        "expect": "default-src 'self'; no 'unsafe-inline' or wildcards",
        "why": "Primary control against cross-site scripting and data injection.",
    },
    {
        "header": "x-content-type-options",
        "label": "nosniff",
        "weight": 1,
        "expect": "nosniff",
        "why": "Stops MIME confusion attacks in older browsers.",
    },
    {
        "header": "x-frame-options",
        "label": "Framing",
        "weight": 1,
        "expect": "DENY or SAMEORIGIN (or CSP frame-ancestors)",
        "why": "Prevents clickjacking via embedded frames.",
    },
    {
        "header": "referrer-policy",
        "label": "Referrer",
        "weight": 1,
        "expect": "strict-origin-when-cross-origin or no-referrer",
        "why": "Stops URL and token leakage to third parties.",
    },
    {
        "header": "permissions-policy",
        "label": "Permissions",
        "weight": 1,
        "expect": "camera=(), microphone=(), geolocation=()",
        "why": "Explicitly denies powerful browser features.",
    },
    {
        "header": "cross-origin-opener-policy",
        "label": "COOP",
        "weight": 1,
        "expect": "same-origin",
        "why": "Isolates the browsing context from cross-origin openers.",
    },
    {
        "header": "cross-origin-resource-policy",
        "label": "CORP",
        "weight": 1,
        "expect": "same-origin or same-site",
        "why": "Blocks cross-origin reads of subresources.",
    },
    {
        "header": "cross-origin-embedder-policy",
        "label": "COEP",
        "weight": 1,
        "expect": "require-corp",
        "why": "Required for cross-origin isolation (SharedArrayBuffer etc.).",
    },
    {
        "header": "x-xss-protection",
        "label": "Legacy XSS filter",
        "weight": 0.5,
        "expect": "0 (the filter is deprecated; disable it cleanly)",
        "why": "Modern guidance is to disable the legacy auditor, not enable it.",
    },
    {
        "header": "cache-control",
        "label": "Cache policy",
        "weight": 0.5,
        "expect": "no-store on authenticated responses",
        "why": "Prevents sensitive pages being written to shared caches.",
    },
    {
        "header": "x-powered-by",
        "label": "Stack disclosure",
        "weight": 0.5,
        "expect": "absent",
        "why": "Removing it raises the cost of targeted exploitation.",
    },
    {
        "header": "server",
        "label": "Server banner",
        "weight": 0.5,
        "expect": "vendor only, no version",
        "why": "Version banners hand attackers a CVE shortlist.",
    },
]

# ── passive search dorks (templates only, nothing is queried) ──────────────

DORKS: list[str] = [
    'site:{d} ext:pdf',
    'site:{d} ext:docx OR ext:xlsx OR ext:pptx',
    'site:{d} intitle:"index of"',
    'site:{d} inurl:admin',
    'site:{d} inurl:login OR inurl:signin',
    'site:{d} inurl:api OR inurl:graphql',
    'site:{d} inurl:backup OR inurl:.bak OR inurl:.old',
    'site:{d} inurl:".git" OR inurl:".env"',
    'site:{d} inurl:phpinfo.php',
    'site:{d} inurl:wp-content OR inurl:wp-admin',
    'site:{d} intext:"api_key" OR intext:"apikey" OR intext:"secret"',
    'site:{d} intext:"BEGIN RSA PRIVATE KEY"',
    'site:{d} intext:"internal use only" OR intext:"confidential"',
    'site:{d} intitle:"dashboard" OR intitle:"portal"',
    'site:{d} inurl:jenkins OR inurl:gitlab OR inurl:grafana',
    'site:github.com "{d}"',
    'site:pastebin.com "{d}"',
    'site:trello.com "{d}"',
    'site:docs.google.com "{d}"',
    '"{d}" -site:{d}',
]

# ── phone / misc ───────────────────────────────────────────────────────────

COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111",
    "1234567", "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein",
    "696969", "shadow", "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890",
    "michael", "654321", "pussy", "superman", "1qaz2wsx", "7777777", "fuckyou", "121212",
    "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan", "jennifer", "zxcvbnm",
    "asdfgh", "hunter", "buster", "soccer", "harley", "batman", "andrew", "tigger",
    "sunshine", "iloveyou", "fuckme", "2000", "charlie", "robert", "thomas", "hockey",
    "ranger", "daniel", "starwars", "klaster", "112233", "george", "asshole", "computer",
    "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111", "131313",
    "freedom", "777777", "pass", "fuck", "maggie", "159753", "aaaaaa", "ginger",
    "princess", "joshua", "cheese", "amanda", "summer", "love", "ashley", "6969",
    "nicole", "chelsea", "biteme", "matthew", "access", "yankees", "987654321", "dallas",
    "austin", "thunder", "taylor", "matrix", "welcome", "admin", "login", "passw0rd",
    "p@ssw0rd", "root", "toor", "changeme", "secret", "default", "guest", "qwerty123",
    "password1", "password123", "letmein123", "iloveyou1", "welcome1", "admin123",
}

COMMON_PORTS: dict[int, str] = {
    20: "FTP data", 21: "FTP control", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 69: "TFTP", 79: "Finger", 80: "HTTP", 81: "HTTP alt", 88: "Kerberos",
    110: "POP3", 111: "rpcbind", 119: "NNTP", 123: "NTP", 135: "MS RPC", 137: "NetBIOS",
    139: "NetBIOS session", 143: "IMAP", 161: "SNMP", 162: "SNMP trap", 179: "BGP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE", 512: "rexec",
    513: "rlogin", 514: "rsh/syslog", 587: "SMTP submission", 636: "LDAPS", 873: "rsync",
    990: "FTPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP", 2049: "NFS", 2181: "ZooKeeper", 2375: "Docker API",
    2376: "Docker TLS", 3000: "Grafana/Node", 3306: "MySQL", 3389: "RDP", 4369: "Erlang EPMD",
    5000: "UPnP/Flask", 5432: "PostgreSQL", 5601: "Kibana", 5672: "RabbitMQ", 5900: "VNC",
    5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes API", 7001: "WebLogic", 8000: "HTTP alt",
    8080: "HTTP proxy", 8081: "HTTP alt", 8443: "HTTPS alt", 8888: "Jupyter", 9000: "PHP-FPM",
    9092: "Kafka", 9200: "Elasticsearch", 9300: "Elasticsearch transport", 11211: "Memcached",
    27017: "MongoDB", 27018: "MongoDB shard", 50000: "SAP", 61616: "ActiveMQ",
}

RISKY_TLDS = {
    "zip", "mov", "tk", "gq", "ml", "ga", "cf", "top", "work", "click", "link", "country",
    "stream", "download", "loan", "review", "win", "bid", "date", "trade", "party", "science",
    "faith", "racing", "account", "men", "cricket", "cam", "rest", "buzz", "monster", "sbs",
    "cyou", "icu", "cfd", "best", "life", "surf", "bar", "quest", "bond", "gdn", "xin",
}

PHISH_KEYWORDS = [
    "login", "signin", "sign-in", "secure", "security", "verify", "verification", "account",
    "update", "confirm", "password", "billing", "invoice", "payment", "wallet", "recovery",
    "unlock", "suspend", "alert", "support", "helpdesk", "gift", "bonus", "claim", "prize",
    "free", "telegram", "whatsapp", "airdrop", "metamask", "seed", "kyc", "refund",
]

CONFUSABLE_LOOKALIKES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ν": "v", "ο": "o",
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "ı": "i", "ȷ": "j", "℩": "i", "ⅼ": "l", "Ⅰ": "l", "Ⅴ": "v", "Ⅹ": "x",
    "０": "0", "１": "1", "２": "2", "３": "3", "４": "4", "５": "5", "６": "6",
    "７": "7", "８": "8", "９": "9",
}
