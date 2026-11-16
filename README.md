# 0SWALD

A private, self-hosted Discord bot for OSINT work on **public, documented
sources**: DNS, WHOIS/RDAP, certificate transparency, public APIs and public
ledger data.

- **360 top-level commands**, or **379 catalogued operations** counting every `gen` subcommand: 117 intelligence lookups, 100 payload-craft commands, 110 local toolkit operations, 22 generator operations, six vanity/username watchtower commands, the operator/appearance controls and the access console.
- **Prefix commands** (default `.`) and **slash commands** in servers and bot DMs: ten category wrappers (`/net` … `/tools`) with autocomplete, plus direct `/vpncheck`, `/ip`, `/help` and owner-only `/sync`.
- **Private by default**: only owners and explicitly approved Discord IDs can run anything.
- **Components V2 output**: results are sent as monochrome containers with white command badges, a numbered section index, linked references, next-lookup pivots and section-aware V2 pagination (page ranges, jump menu). `.vpncheck` uses a purpose-built verdict card — exposure meter, signal row and source buttons. No traditional embed payload is sent.
- **One white application emoji per command**, generated locally with OpenCV on a dark rounded tile. The full set is uploaded once and reused on later boots.
- **A static monochrome website** in `site/`: terminal demo, the full command index, an embed studio, an access console and operating notes.
- **Runs on a Windows laptop** with Python only. No Linux, Docker, WSL or cloud account required.

> **Responsible use.** This is a research and defensive-security tool. Query only
> infrastructure you own or are authorised to assess, and respect local law,
> privacy expectations and each service's terms. The operator of an instance is
> accountable for how it is used. The bot never touches leaked credential dumps,
> breach marketplaces, private accounts or people-search databases, and it does
> not attempt logins, cracking or unauthorised access.

---

## 1. Requirements

| Item | Detail |
|---|---|
| OS | Windows 10 or Windows 11 (also works on macOS/Linux) |
| Python | 3.11 or newer — [python.org/downloads/windows](https://www.python.org/downloads/windows/) |
| Discord | A Discord account and a server where you can add bots |
| Disk | ~50 MB including dependencies |
| Network | Outbound HTTPS and TCP/43 (WHOIS) and TCP/443 |

During Python installation **tick "Add python.exe to PATH"** — the setup script
depends on it.

---

## 2. Create the Discord application

1. Open <https://discord.com/developers/applications> → **New Application**.
2. Name it (for example `0SWALD`) and accept the terms.
3. Go to **Bot** → **Reset Token** → copy the token. This is `DISCORD_TOKEN`.
4. Still on **Bot**, scroll to **Privileged Gateway Intents** and enable:
   - **MESSAGE CONTENT INTENT** — *required* for prefix commands.
   - Server Members Intent is **not** needed.
5. Go to **OAuth2 → URL Generator**:
   - Scopes: `bot`, `applications.commands`
   - Bot permissions: `View Channels`, `Send Messages`, `Embed Links`, `Attach Files`, `Read Message History`, `Add Reactions`, `Use External Emojis`
   - Open the generated URL and add the bot to your private server.
6. Enable **Developer Mode** in Discord (User Settings → Advanced) so you can
   right-click your name → **Copy User ID**. That numeric ID is your `OWNER_IDS`.

---

## 3. Install on Windows

1. Put this folder somewhere permanent, e.g. `C:\0SWALD`.
2. Double-click **`install.bat`**.
   It creates `.venv`, installs `requirements.txt`, and copies `.env.example` to `.env`.
3. Open **`.env`** in Notepad and set at minimum:

```ini
DISCORD_TOKEN=your-bot-token-here
OWNER_IDS=123456789012345678
COMMAND_PREFIX=.
GUILD_ID=your-private-server-id
```

The slash tree is registered **once, globally**, so the same commands work in
every server and in bot DMs. `GUILD_ID` no longer receives a second copy: on the
first sync after upgrading it is used to delete guild-scoped copies left by older
builds, which is what made every command appear twice. Global propagation can
take up to an hour; restarting Discord refreshes the client cache. Set
`USER_INSTALL=true` only after enabling User Install in the Developer Portal —
see section 5.

4. Double-click **`run.bat`**.

You should see the banner, then `connected as 0SWALD#1234`. In your server:

```text
.help
.whoami
.approve 987654321098765432
```

The first account is you (owner, automatic). Approve anyone else by ID.

### Manual alternative

```bat
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env
.venv\Scripts\python.exe bot.py
```

---

## 4. Private access model

| Layer | Behaviour |
|---|---|
| Owners (`OWNER_IDS`) | Always allowed, including during maintenance |
| Approved users | Stored in `data/osint.sqlite3`, added with `.approve <id>` |
| Everyone else | Denied before any command executes; the attempt is logged |
| Maintenance mode | `.maintenance on` restricts everything to owners |
| DMs | Prefix and slash commands are allowed for approved users unless `ALLOW_DMS=false` |
| Audit | Every lookup is written to SQLite and, if `LOG_CHANNEL_ID` is set, mirrored to that channel |

Admin commands: `approve`, `revoke`, `approvals`, `audit`, `prefix`, `maintenance`,
`appearance`, `reload`, `sync`, `stats`, `sources`, `apikeys`, `botinvite`, `about`, `shutdown`.

`approve` is owners-only, so a compromised approved account cannot widen access.

### Slash commands in DMs

The global tree covers servers and bot DMs by default. Group DMs and other
private channels need the User Install context, which is opt-in because
requesting it without the portal toggle makes Discord reject the whole sync:

1. In the Developer Portal → **Installation**, enable **User Install**.
2. Set `USER_INSTALL=true` in `.env` and restart (or run `/sync`).
3. Run `.botinvite` as the owner and open **Add to your account for DMs and group DMs** (the `integration_type=1` link). This grants `applications.commands` only — no server permissions.

Then run `.sync` as owner, or restart the bot. Guild copies update instantly;
the global copy can take up to an hour to appear in DMs. In a group DM, add the
OSINT app as a member and run `/help` or `/net`. Access control still applies:
unapproved users are denied before any lookup runs.

### Appearance

The default is minimal: no author line, title block, summary, pipeline, checks,
risk bar, source list or footer. Each result opens with its custom command emoji,
keeps the data fields and only surfaces failed checks as warnings. A 128×128
OpenCV badge is generated for every command and also uploaded as an
application-owned Discord emoji, so it works in servers, DMs and group DMs.
Owners can change the style without editing code:

```text
.appearance                              show the current settings
.appearance theme clean|classic|mono|neon
.appearance set brand "My Intel Bot"
.appearance set footer "internal use only"
.appearance set numbers on|off
.appearance set icons on|off
.appearance set pipeline on|off
.appearance set minimal on|off
.appearance set thumbnails on|off
.appearance set checks text|emoji
.appearance set summary on|off
.appearance set author on|off
.appearance set compact on|off
.appearance color network #4A90E2
.appearance color all #4A90E2
.appearance color network reset
.appearance preview
.appearance reset
```

`clean` is the default minimal layout. `classic` restores the author line,
title, summary, check blocks, risk bar, footer and numbered sections. `mono` is
minimal with a slate accent. `neon` restores the vivid full-detail look. Set
`minimal off` to bring the older layout back without switching themes. Settings
persist in `data/osint.sqlite3`.

The first start after deploying imports `opencv-python-headless`, creates one
badge per command and uploads the missing ones as application emojis in the
background. Later starts only fetch the existing IDs. If Discord or OpenCV is
unavailable, results still render with their data and attached badge thumbnail.

---

## 5. Command catalogue (360 top-level commands)

| Category | Count | Highlights |
|---|---:|---|
| **Network** | 26 | `ip`, `geo`, `asn`, `asnprefixes`, `bgppeers`, `netblock`, `ipv6`, `mac`, `rdns`, `portcheck`, `headers`, `httpstatus`, `tls`, `cdn`, `rbl`, `whoisip`, `myip`, `subnetinfo`, `supernet`, `ipv6type`, `portrange`, `tcpflags`, `icmpcode`, `dnstype`, `ciphersuite`, `rangeexpand` |
| **Domain** | 26 | `dns`, `a`, `aaaa`, `mx`, `txt`, `ns`, `cname`, `soa`, `caa`, `srv`, `spf`, `dmarc`, `dkim`, `dnssec`, `emailposture`, `whois`, `rdap`, `domainage`, `crtsh`, `subdomains`, `propagation`, `punycode`, `tldinfo`, `authresults`, `received`, `idnlabels` |
| **Web** | 30 | `url`, `expand`, `tech`, `secheaders`, `robots`, `sitemap`, `securitytxt`, `cookies`, `cors`, `methods`, `favicon`, `waf`, `phish`, `dorks`, `metatags`, plus `phishmask`, `phishlure`, `phishdork`, `phishkit`, `typosquat`, `homoglyph`, `dehomoglyph`, `confusable`, `urlentropy`, `urlunwrap`, `redirparams`, `defang`, `refang`, `iocs`, `httphdr` |
| **Identity** | 16 | `email`, `emailbreach`, `gravatar`, `username`, `msisdn`, `password`, `pwnedpass`, `hash`, `jwt`, `uuid`, `timestamp`, `decode`, `encode`, `useragent`, `iban`, `sshkey` |
| **Social** | 17 | `github`, `ghrepos`, `gitlab`, `reddit`, `redditsub`, `hackernews`, `devto`, `stackoverflow`, `npm`, `pypi`, `steam`, `minecraft`, `roblox`, `telegram`, `keybase`, `mastodon`, `bluesky` |
| **Discord** | 22 | `snowflake`, `accountage`, `invite`, `userinfo`, `guildinfo`, `avatar`, `banner`, `webhook`, `emoji`, `status`, `vanitycheck`, `vanitysnipe`, `usernamecheck`, `usernamesnipe`, `sniperlist`, `sniperstop`, `tokentype`, `snowflakerange`, `perms`, `intents`, `oauthscopes`, `fakesnowflake` |
| **Vulnerability** | 12 | `cve`, `cvesearch`, `nvdrecent`, `kev`, `epss`, `cwe`, `cvss`, `bazaar`, `urlscan`, `virustotal`, `shodan`, `abuseipdb` |
| **Crypto** | 7 | `btc`, `btctx`, `block`, `eth`, `ethtx`, `sol`, `address` |
| **Craft** | 40 | `caesar`, `uncaesar`, `vigenere`, `railfence`, `bacon`, `base58`, `base85`, `hexdump`, `xorhex`, `zerowidth`, `leet`, `nato`, `freq`, `iocs`, `adler32`, `fnv1a`, `pbkdf2`, `hashmode`, `readability` and the rest of the local payload helpers |
| **Toolkit** | 130 | Encoders, hashes, JSON, CIDR arithmetic, HTTP metadata, dates, numbers, colours, validation and text transforms |
| **Generator** | 22 (+7 craft) | Synthetic emails, secrets, cards, IBANs, snowflakes and fixture data |

Every command has a detailed `help` page:

```text
.help dns
.help username
```

and autocomplete in slash mode:

```text
/net command:dns args:example.com
/identity command:username args:somehandle
/vpncheck address:1.1.1.1
/ip address:8.8.8.8
/sync                          (owner only)
```

---

## 6. Optional API keys

Nothing below is required to boot. A command whose key is missing returns a
setup card instead of failing. Add values to `.env`, then restart or `.reload`.

| Variable | Service | Unlocks | Cost |
|---|---|---|---|
| `GITHUB_TOKEN` | GitHub | 60 → 5,000 requests/hour | free |
| `HIBP_API_KEY` | Have I Been Pwned | Per-email breach history | paid (~$3.95/mo) |
| `STEAM_API_KEY` | Steam | Web API enrichment | free |
| `VIRUSTOTAL_API_KEY` | VirusTotal | Multi-engine reputation | free tier |
| `SHODAN_API_KEY` | Shodan | Host exposure | free tier |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | Abuse confidence | free tier |
| `URLSCAN_API_KEY` | urlscan.io | Submitting scans | free |
| `ABUSECH_AUTH_KEY` | abuse.ch | MalwareBazaar metadata | free |
| `NVD_API_KEY` | NIST NVD | 5 → 50 requests/30s | free |
| `TWITCH_CLIENT_ID` / `_SECRET` | Twitch | Reserved for future use | free |

Password exposure checks (`pwnedpass`) work **without** any key via the
k-anonymity range API.

---

## 7. Project layout

```text
bot.py                  entry point, access gate, audit feed, error policy
config.py               .env loading and optional-key registry
core/
  embeds.py             Intel embed builder (the house style)
  http.py               shared aiohttp client: cache, throttle, retry
  store.py              SQLite: approvals, prefixes, audit, metrics
  checks.py             owner / approval predicates
  utils.py              formatting, validation, snowflakes, targets
  dns.py                DNS-over-HTTPS resolver (4 providers)
  whois.py              raw port-43 WHOIS with IANA referral
  tls.py                socket-level certificate inspection
  signatures.py         tech/WAF/CDN/hash/mail/username tables
cogs/arsenal.py         100 payload-craft commands: ciphers, lure analysis, hashes, probes
cogs/watchtower.py      vanity/username checkers and the polling sniper
site/                   monochrome website: terminal, command index, embed studio
  cvss.py               CVSS v3.1 base score calculator
  v2.py                 Components V2 renderer and automatic pagination
  ui.py                 V2 pagination and confirmation views
  command.py            the @intel decorator (metadata + cooldowns)
  visuals.py            monochrome cv2 command badges
  emojis.py             application emoji registry and per-command markup
  emoji_sync.py         one-time badge upload and reconciliation
cogs/                   one module per intelligence category, plus toolkit and generator
data/osint.sqlite3      created at first run (gitignored)
logs/bot.log            rotating log (gitignored)
```

Adding a command is one method plus a decorator:

```python
@intel(
    category="network",
    brief="One-line description for help and autocomplete.",
    usage="<target>",
    aliases=["short"],
    examples=["mycmd example.com"],
    sources=["some.public.api"],
)
async def mycmd(self, ctx, target: str = None):
    await ack(ctx)
    data = await self.net.get_json("https://api.example.com/lookup")
    embed = Intel(category="network", command="mycmd", ctx=ctx, target=target)
    embed.kv("PANEL", {"Key": data.get("value")}, inline=True)
    embed.source("some.public.api")
    await embed.send(ctx)
```

Categories are wired into `COGS` in `bot.py` and `GROUPS` in `cogs/dispatch.py`. Generator operations live under the `gen` group: `.gen email`, `.gen password 32`, `.gen uuid` and similar. The toolkit covers encoders, hashes, JSON, CIDR arithmetic, HTTP metadata, dates, numbers, colours and text transforms. The arsenal covers payload crafts, and every command in it is a single function plus one registry tuple. The complete new-command catalog is in [NEW-COMMANDS.md](NEW-COMMANDS.md).

### Website

`site/` is a static, dependency-free monochrome site — no build step, no CDN, no
analytics. The look is a dark product console: a glass navigation bar, a hero
with the offline shell and floating proof chips, a command ticker, bento
capability tiles and a generated command index (`assets/v4.css`).

| Page | Contents |
|---|---|
| `site/index.html` | Hero with the offline terminal demo and proof chips, a command ticker, the report plate, capability bento, a category rail with featured commands, the two operator tools and a three-step deploy path |
| `site/commands.html` | Full command index: search by name, alias, purpose or usage; twelve category filters; pagination; open any command for every alias it answers to and the commands related to it |
| `site/embeds.html` | Embed studio: message content plus three embeds, markdown preview, drag-ordered fields, templates, validation, undo/redo, import/export, JSON, single-embed and `curl` output |
| `site/access.html` | Access console: mirrors `core/access.py`, previews the decision each persona gets, flags risky settings and emits one `.accessimport` line |
| `site/docs.html` | Operating notes: deployment, environment, layout, report layout, watchtower, limits, optional keys and responsible use |
| `site/assets/commands.js` | Generated catalogue (`python tools/build_catalog.py`) — read from the cogs, so the site cannot drift from the bot |
| `site/assets/command-drawer.js` | Command detail drawer: aliases, usage, sources and related commands, with deep links (`#cmd-<name>`) |

Serve it locally:

```bat
py -3 -m http.server 8000 --directory site
```

Then open <http://localhost:8000>. Each page is one job; the shared shell lives in
`assets/site.js`. The access console works offline: it never calls the bot. It
edits a copy of the configuration, writes `localStorage`, and you carry the
generated `.accessimport` line across yourself. Drafts in the embed studio stay
in your browser, and the catalogue is rebuilt with `python tools/build_catalog.py`
whenever a command is added or renamed.

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Login failed: DISCORD_TOKEN is invalid` | Reset the token in the Developer Portal and update `.env` |
| `MESSAGE CONTENT INTENT is not enabled` | Bot → Privileged Gateway Intents → enable and save |
| Prefix commands do nothing | Message Content Intent, or your ID is not approved (`.whoami`) |
| Slash commands missing | Restart or run `/sync` (or `.sync`) as owner; the reply names any command Discord rejected. Group DMs need User Install enabled **and** `USER_INSTALL=true`, plus the app added to your account (`.botinvite`); global propagation can take up to an hour |
| Slash commands appear twice | Run `/sync` (or `.sync`): guild-scoped copies from older builds are deleted so only the global tree remains, then restart Discord |
| `.help` works but lookups fail | Outbound firewall blocking HTTPS or TCP/43; check `logs/bot.log` |
| Reddit lookups 403 | Reddit blocks data-centre IPs; rerun later or from home broadband |
| crt.sh 502 / timeouts | The public instance throttles; wait a minute and retry |
| NVD "rate limited" | Add `NVD_API_KEY` (Free) or wait 30 seconds |
| Emoji/unicode look wrong in console | `run.bat` sets UTF-8; use Windows Terminal for best results |
| `python` not found | Reinstall Python with "Add python.exe to PATH" ticked |
| Gateway keeps reconnecting | Check antivirus/VPN filtering WebSocket traffic |

Logs: `logs/bot.log`. Database: `data/osint.sqlite3` (back it up; it contains
your allow-list).

---

## 9. Security notes for operators

- `.env` contains your bot token. It is gitignored — never commit or share it.
  If it leaks, reset the token immediately.
- The bot has no message-content logging: it reads only messages that start with
  the prefix, and it never stores lookup arguments beyond the command name.
- Approved users can query public data. They cannot read your token, database or
  other users' DMs.
- Keep the allow-list small. Use `.maintenance on` before investigating abuse.
- Every lookup is auditable through `.audit`, and optionally streamed to a
  private channel.

---

## 10. Wispbyte hosting and live updates

The live instance runs from the `wispbyte` branch. Wispbyte pulls that branch
when the server starts, and the running bot polls it every 60 seconds. A new
commit is cloned, checked for syntax errors, installed and activated with a
self-restart. `.env`, `data/`, `logs/` and `.local/` are never replaced by an
update.

Put the Discord credentials in `/home/container/.env` (Files → root → `.env`):

```ini
DISCORD_TOKEN=your-bot-token-here
OWNER_IDS=your-discord-user-id
```

`OWNER_IDS` accepts a comma-separated list. Never put the token in the startup
command, the repository or a GitHub commit.

---

## 11. Licence and attribution

Runs on [discord.py](https://github.com/Rapptz/discord.py) (MIT). All data
remains the property of the upstream provider; this project only reads public
interfaces. No warranty is provided — verify anything you intend to act on.
