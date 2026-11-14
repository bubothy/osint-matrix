# OSINT MATRIX

A private, self-hosted Discord intelligence console modelled on the command-heavy
feel of Heist / Bleed / Greed — but built entirely around **legitimate, documented
OSINT sources**: DNS, WHOIS/RDAP, certificate transparency, public APIs and public
ledger data.

- **117 intelligence commands** across eight categories, plus **18 operator commands**.
- **Prefix commands** (default `.`) and **slash shortcuts** (`/net`, `/domain`, `/web`, `/identity`, `/social`, `/discord`, `/vuln`, `/crypto`) in servers, bot DMs and group DMs.
- **Private by design**: only owners and explicitly approved Discord IDs can run anything.
- **Readable embeds**: compact data panes, optional risk accents, pass/fail checks, and a clean source/latency footer. Operators can switch themes, colors and layout with `.appearance`.
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
2. Name it (for example `OSINT MATRIX`) and accept the terms.
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

1. Put this folder somewhere permanent, e.g. `C:\OSINT-MATRIX`.
2. Double-click **`install.bat`**.
   It creates `.venv`, installs `requirements.txt`, and copies `.env.example` to `.env`.
3. Open **`.env`** in Notepad and set at minimum:

```ini
DISCORD_TOKEN=your-bot-token-here
OWNER_IDS=123456789012345678
COMMAND_PREFIX=.
GUILD_ID=your-private-server-id
```

`GUILD_ID` makes the slash commands appear instantly in that server. They are
also synced globally so the same commands work in bot DMs and group DMs; Discord
may take up to an hour to propagate the global copy.

4. Double-click **`run.bat`**.

You should see the banner, then `connected as OSINT MATRIX#1234`. In your server:

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

### Slash commands in DMs and group DMs

Slash commands are global and include the `BOT_DM` and `PRIVATE_CHANNEL`
contexts. Two one-time steps make them visible outside a server:

1. In the Developer Portal → **Installation**, enable **User Install**.
2. Run `.botinvite` as the owner and open **Add to your account for DMs and group DMs** (the `integration_type=1` link). This grants `applications.commands` only — no server permissions.

Then run `.sync` as owner, or restart the bot. Guild copies update instantly;
the global copy can take up to an hour to appear in DMs. In a group DM, add the
OSINT app as a member and run `/help` or `/net`. Access control still applies:
unapproved users are denied before any lookup runs.

### Appearance

The default style is deliberately plain: no numbered sections, no pipeline
block, and no emoji status markers. Owners can change it without editing code:

```text
.appearance                              show the current settings
.appearance theme clean|classic|mono|neon
.appearance set brand "My Intel Bot"
.appearance set footer "internal use only"
.appearance set numbers on|off
.appearance set icons on|off
.appearance set pipeline on|off
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

`clean` is the default: no descriptive summary, no numbered sections, no
pipeline block. `classic` restores the summary, numbered sections and pipeline
steps. `mono` removes the author line, summary and emoji, and uses a slate
accent. `neon` restores the vivid full-detail look. Settings persist in
`data/osint.sqlite3`.

---

## 5. Command catalogue (117 intel commands)

| Category | Count | Highlights |
|---|---:|---|
| **Network** | 17 | `ip`, `geo`, `asn`, `asnprefixes`, `bgppeers`, `netblock`, `ipv6`, `mac`, `rdns`, `portcheck`, `headers`, `httpstatus`, `tls`, `cdn`, `rbl`, `whoisip`, `myip` |
| **Domain** | 23 | `dns`, `a`, `aaaa`, `mx`, `txt`, `ns`, `cname`, `soa`, `caa`, `srv`, `spf`, `dmarc`, `dkim`, `dnssec`, `emailposture`, `whois`, `rdap`, `domainage`, `crtsh`, `subdomains`, `propagation`, `punycode`, `tldinfo` |
| **Web** | 15 | `url`, `expand`, `tech`, `secheaders`, `robots`, `sitemap`, `securitytxt`, `cookies`, `cors`, `methods`, `favicon`, `waf`, `phish`, `dorks`, `metatags` |
| **Identity** | 16 | `email`, `emailbreach`, `gravatar`, `username`, `msisdn`, `password`, `pwnedpass`, `hash`, `jwt`, `uuid`, `timestamp`, `decode`, `encode`, `useragent`, `iban`, `sshkey` |
| **Social** | 17 | `github`, `ghrepos`, `gitlab`, `reddit`, `redditsub`, `hackernews`, `devto`, `stackoverflow`, `npm`, `pypi`, `steam`, `minecraft`, `roblox`, `telegram`, `keybase`, `mastodon`, `bluesky` |
| **Discord** | 10 | `snowflake`, `accountage`, `invite`, `userinfo`, `guildinfo`, `avatar`, `banner`, `webhook`, `emoji`, `status` |
| **Vulnerability** | 12 | `cve`, `cvesearch`, `nvdrecent`, `kev`, `epss`, `cwe`, `cvss`, `bazaar`, `urlscan`, `virustotal`, `shodan`, `abuseipdb` |
| **Crypto** | 7 | `btc`, `btctx`, `block`, `eth`, `ethtx`, `sol`, `address` |

Every command has a detailed `help` page:

```text
.help dns
.help username
```

and autocomplete in slash mode:

```text
/net command:dns args:example.com
/identity command:username args:somehandle
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
  cvss.py               CVSS v3.1 base score calculator
  ui.py                 pagination and confirmation views
  command.py            the @intel decorator (metadata + cooldowns)
cogs/                   one module per intelligence category
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

Categories are wired into `COGS` in `bot.py` and `GROUPS` in `cogs/dispatch.py`.

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Login failed: DISCORD_TOKEN is invalid` | Reset the token in the Developer Portal and update `.env` |
| `MESSAGE CONTENT INTENT is not enabled` | Bot → Privileged Gateway Intents → enable and save |
| Prefix commands do nothing | Message Content Intent, or your ID is not approved (`.whoami`) |
| Slash commands missing | Restart or run `.sync` as owner. DMs/group DMs also need User Install enabled and the app added to your account (`.botinvite`); global propagation can take up to an hour |
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

## 10. Licence and attribution

Runs on [discord.py](https://github.com/Rapptz/discord.py) (MIT). All data
remains the property of the upstream provider; this project only reads public
interfaces. No warranty is provided — verify anything you intend to act on.
