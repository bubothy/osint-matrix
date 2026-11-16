"""Synthetic data generators for test fixtures and safe demonstrations.

Nothing here resembles a real person, account or payment instrument. Addresses
use reserved documentation ranges, phone numbers use fiction ranges, and e-mail
defaults to example.com. Output is intentionally deterministic only in format,
never in value.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import math
import random
import secrets
import string
import uuid
from typing import Any

from discord.ext import commands

from core.embeds import Intel, notice, respond
from core.errors import UsageError
from core.utils import ack, clip, is_domain, normalize_host

_WORDS = (
    "amber", "anchor", "atlas", "brisk", "cedar", "cinder", "cobalt", "comet",
    "coral", "crypt", "delta", "ember", "falcon", "fern", "flint", "frost",
    "garnet", "glade", "harbor", "hazel", "indigo", "ivory", "juniper", "kestrel",
    "lantern", "lunar", "maple", "marble", "meadow", "meteor", "mint", "north",
    "oak", "onyx", "orbit", "pearl", "pine", "quartz", "raven", "reef",
    "river", "rogue", "saffron", "sable", "silver", "slate", "solar", "spruce",
    "storm", "summit", "tundra", "umber", "valley", "velvet", "violet", "willow",
    "winter", "zephyr", "zinc", "atlas", "beacon", "cipher", "drift", "echo",
)
_ADJECTIVES = (
    "able", "brisk", "calm", "clever", "crisp", "eager", "faint", "gentle",
    "grand", "hollow", "keen", "light", "lucky", "mellow", "nimble", "plain",
    "quiet", "rapid", "ready", "sharp", "silent", "smooth", "steady", "sunny",
    "swift", "tidy", "vivid", "warm", "wise", "young",
)
_NOUNS = (
    "badger", "beacon", "birch", "canyon", "cedar", "comet", "cove", "crow",
    "dawn", "delta", "dune", "ember", "falcon", "fern", "field", "finch",
    "flame", "fox", "glade", "harbor", "heron", "hill", "isle", "juniper",
    "kite", "lake", "lark", "maple", "marsh", "meadow", "mist", "moon",
    "oak", "orbit", "otter", "pebble", "pine", "rain", "raven", "reef",
    "ridge", "river", "robin", "rock", "sail", "shore", "sky", "slate",
    "snow", "sparrow", "spruce", "star", "stone", "storm", "sun", "thistle",
    "tide", "trail", "vale", "willow", "wind", "wolf", "wren", "zephyr",
)
_FIRST = ("Avery", "Blair", "Casey", "Drew", "Ellis", "Finley", "Gray", "Harper", "Indigo", "Jules", "Kai", "Lane", "Marlow", "Noor", "Oakley", "Parker", "Quinn", "Reese", "Sage", "Tatum")
_LAST = ("Arden", "Bell", "Carter", "Dale", "Ellery", "Finch", "Gale", "Hale", "Ivy", "Jones", "Kerr", "Lark", "Mercer", "North", "Orion", "Pace", "Quill", "Reyes", "Stone", "Vale")
_COMPANIES = ("Northstar", "Cobalt", "Harbor", "Juniper", "Meridian", "Orchard", "Pinecrest", "Redwood", "Summit", "Willow")
_SUFFIXES = ("Labs", "Works", "Systems", "Group", "Studio", "Networks")
_JOBS = ("Analyst", "Engineer", "Researcher", "Designer", "Operator", "Technician", "Coordinator", "Consultant")

_USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
)


def _word() -> str:
    return secrets.choice(_WORDS)


def _digits(count: int) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(count))


def _letters(count: int) -> str:
    return "".join(secrets.choice(string.ascii_lowercase) for _ in range(count))


def _email(domain: str | None) -> tuple[str, str]:
    host = normalize_host(domain or "example.com") or "example.com"
    if not is_domain(host):
        raise UsageError("Supply a valid domain, for example `example.com`.")
    local = f"{secrets.choice(_ADJECTIVES)}.{secrets.choice(_NOUNS)}{_digits(3)}"
    return local, f"{local}@{host}"


def _password(length: int = 20) -> str:
    length = max(8, min(128, length))
    pools = (string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%^&*()-_=+[]{};:,.?")
    value = [secrets.choice(pool) for pool in pools]
    alphabet = "".join(pools)
    value.extend(secrets.choice(alphabet) for _ in range(length - len(value)))
    secrets.SystemRandom().shuffle(value)
    return "".join(value)


def _passphrase(words: int = 4) -> str:
    words = max(3, min(8, words))
    return "-".join(secrets.choice(_WORDS) for _ in range(words)) + f"-{_digits(2)}"


def _username() -> str:
    return f"{secrets.choice(_ADJECTIVES)}_{secrets.choice(_NOUNS)}{_digits(2)}"


def _handle() -> str:
    return f"@{secrets.choice(_NOUNS)}{secrets.choice(_ADJECTIVES).title()}{_digits(2)}"


def _name() -> str:
    return f"{secrets.choice(_FIRST)} {secrets.choice(_LAST)}"


def _address() -> str:
    number = secrets.randbelow(9000) + 100
    return f"{number} Example {secrets.choice(('Street', 'Avenue', 'Road', 'Lane'))}, Springfield, IL 62701"


def _phone(region: str | None) -> str:
    key = (region or "US").strip().upper()
    if key in {"UK", "GB", "UNITED KINGDOM"}:
        return f"+44 20 7946 0{_digits(3)}"
    if key in {"US", "USA", "UNITED STATES", "CA", "CANADA"}:
        return f"+1 555 01{_digits(2)}"
    return f"+1 555 01{_digits(2)}"


def _ulid() -> str:
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    timestamp = int(dt.datetime.now(dt.timezone.utc).timestamp() * 1000)
    time_part = ""
    for _ in range(10):
        time_part = alphabet[timestamp % 32] + time_part
        timestamp //= 32
    randomness = "".join(secrets.choice(alphabet) for _ in range(16))
    return time_part + randomness


def _mac() -> str:
    # Locally administered, unicast prefix; safe for documentation and tests.
    octets = ["02", "00", "00"] + [f"{secrets.randbelow(256):02X}" for _ in range(3)]
    return ":".join(octets)


def _ipv4() -> str:
    block = secrets.choice(("192.0.2", "198.51.100", "203.0.113"))
    return f"{block}.{secrets.randbelow(254) + 1}"


def _ipv6() -> str:
    return f"2001:db8:{secrets.randbelow(65536):x}:{secrets.randbelow(65536):x}::{secrets.randbelow(65536):x}"


def _domain() -> str:
    return f"{secrets.choice(_WORDS)}-{secrets.choice(_ADJECTIVES)}.example"


def _company() -> str:
    return f"{secrets.choice(_COMPANIES)} {secrets.choice(_SUFFIXES)}"


def _job() -> str:
    return f"{secrets.choice(('Junior', 'Senior', 'Lead', 'Principal'))} {secrets.choice(_JOBS)}"


def _isbn() -> str:
    prefix = "978"
    body = prefix + _digits(9)
    total = sum((1 if index % 2 == 0 else 3) * int(char) for index, char in enumerate(body))
    return body + str((10 - total % 10) % 10)


def _otp() -> str:
    return _digits(6)


def _apikey() -> str:
    return "osk_test_" + secrets.token_urlsafe(24)


def _color() -> str:
    return "#" + secrets.token_hex(3).upper()


def _lorem() -> str:
    return " ".join(secrets.choice(_WORDS) for _ in range(secrets.randbelow(18) + 12)).capitalize() + "."


def _emit(ctx: commands.Context, title: str, pairs: list[tuple[str, Any]], note: str = "") -> Any:
    embed = Intel(
        category="generator",
        command=f"gen {title}",
        ctx=ctx,
        summary="Synthetic test data. It is not linked to a real person or account.",
    )
    for label, value in pairs:
        embed.field(label, value, inline=False)
    if note:
        embed.field("NOTE", note, inline=False)
    embed.source("local computation")
    return embed.send(ctx)


class Generator(commands.Cog, name="Generator"):
    """Create synthetic emails, secrets and fixture data."""

    def __init__(self, bot: Any) -> None:
        self.bot = bot

    @commands.group(
        name="gen",
        aliases=["generate"],
        invoke_without_command=True,
        usage="[type]",
        brief="Synthetic email addresses, passwords and fixture data.",
        help="Run `.gen` for the type list, or `.gen <type>` for one value.",
        extras={"category": "generator"},
    )
    async def gen(self, ctx: commands.Context) -> None:
        """Show the synthetic data generator."""
        await ack(ctx)
        names = (
            "email", "password", "passphrase", "username", "handle", "name",
            "address", "phone", "useragent", "uuid", "ulid", "mac", "ipv4",
            "ipv6", "domain", "company", "job", "isbn", "otp", "apikey",
            "color", "lorem",
        )
        await respond(
            ctx,
            notice(
                "GENERATOR",
                "Synthetic test data for fixtures and demonstrations. Nothing is sent to a third party.",
                category="generator",
                fields=[
                    ("TYPES", "  ".join(f"`{name}`" for name in names), False),
                    ("USE", f"`.gen email` · `.gen password 32` · `.gen phone GB`", False),
                    ("SCOPE", "Reserved domains, documentation IP ranges and fiction phone ranges only.", False),
                ],
                footer="generator  •  local secrets module",
            ),
        )

    @gen.command(name="email", usage="[domain]")
    async def email(self, ctx: commands.Context, domain: str = None) -> None:
        """Generate a synthetic email address."""
        await ack(ctx)
        local, address = _email(domain)
        await _emit(
            ctx,
            "email",
            [
                ("OUTPUT", f"`{address}`"),
                ("LOCAL PART", f"`{local}`"),
                ("DOMAIN", f"`{address.split('@', 1)[1]}`"),
            ],
            "The default domain is example.com; supply one to test a domain you control.",
        )

    @gen.command(name="password", usage="[length]")
    async def password(self, ctx: commands.Context, length: str = None) -> None:
        """Generate a strong random password."""
        await ack(ctx)
        try:
            size = int(length or 20)
        except ValueError:
            raise UsageError("Length must be a number from 8 to 128.") from None
        if not 8 <= size <= 128:
            raise UsageError("Length must be a number from 8 to 128.")
        value = _password(size)
        bits = size * math.log2(94)
        await _emit(
            ctx,
            "password",
            [
                ("OUTPUT", f"```text\n{value}\n```"),
                ("LENGTH", f"`{size}`"),
                ("ALPHABET", "`94 printable ASCII characters`"),
                ("ESTIMATED ENTROPY", f"`{bits:.1f} bits`"),
            ],
            "Generated locally with the operating system CSPRNG. Change storage after use.",
        )

    @gen.command(name="passphrase", usage="[words]")
    async def passphrase(self, ctx: commands.Context, words: str = None) -> None:
        """Generate a hyphenated passphrase."""
        await ack(ctx)
        try:
            count = int(words or 4)
        except ValueError:
            raise UsageError("Word count must be 3–8.") from None
        if not 3 <= count <= 8:
            raise UsageError("Word count must be 3–8.")
        value = _passphrase(count)
        await _emit(
            ctx,
            "passphrase",
            [("OUTPUT", f"```text\n{value}\n```"), ("WORDS", f"`{count}`")],
            "The words come from a small built-in list, so treat this as a fixture rather than a production secret.",
        )

    @gen.command(name="username", usage="")
    async def username(self, ctx: commands.Context) -> None:
        """Generate a synthetic username."""
        await ack(ctx)
        value = _username()
        await _emit(ctx, "username", [("OUTPUT", f"`{value}`")])

    @gen.command(name="handle", usage="")
    async def handle(self, ctx: commands.Context) -> None:
        """Generate a synthetic social handle."""
        await ack(ctx)
        value = _handle()
        await _emit(ctx, "handle", [("OUTPUT", f"`{value}`")])

    @gen.command(name="name", usage="")
    async def name(self, ctx: commands.Context) -> None:
        """Generate a fictional person's name."""
        await ack(ctx)
        await _emit(ctx, "name", [("OUTPUT", f"`{_name()}`")])

    @gen.command(name="address", usage="")
    async def address(self, ctx: commands.Context) -> None:
        """Generate a fictional postal address."""
        await ack(ctx)
        await _emit(ctx, "address", [("OUTPUT", f"`{_address()}`")], "The city and postcode are illustrative, not a real residence.")

    @gen.command(name="phone", usage="[region]")
    async def phone(self, ctx: commands.Context, region: str = None) -> None:
        """Generate a reserved-range phone number."""
        await ack(ctx)
        value = _phone(region)
        await _emit(ctx, "phone", [("OUTPUT", f"`{value}`"), ("REGION", f"`{(region or 'US').upper()}`")], "Uses the North American 555-01xx fiction range or the UK 020 7946 0xxx range.")

    @gen.command(name="useragent", usage="")
    async def useragent(self, ctx: commands.Context) -> None:
        """Return a realistic browser User-Agent string."""
        await ack(ctx)
        value = secrets.choice(_USER_AGENTS)
        await _emit(ctx, "useragent", [("OUTPUT", f"```text\n{value}\n```")])

    @gen.command(name="uuid", usage="")
    async def uuid(self, ctx: commands.Context) -> None:
        """Generate a random UUIDv4."""
        await ack(ctx)
        value = str(uuid.uuid4())
        await _emit(ctx, "uuid", [("OUTPUT", f"`{value}`"), ("VERSION", "`4`")])

    @gen.command(name="ulid", usage="")
    async def ulid(self, ctx: commands.Context) -> None:
        """Generate a ULID."""
        await ack(ctx)
        value = _ulid()
        await _emit(ctx, "ulid", [("OUTPUT", f"`{value}`"), ("LENGTH", f"`{len(value)}`")])

    @gen.command(name="mac", usage="")
    async def mac(self, ctx: commands.Context) -> None:
        """Generate a locally administered MAC address."""
        await ack(ctx)
        value = _mac()
        await _emit(ctx, "mac", [("OUTPUT", f"`{value}`"), ("TYPE", "`locally administered, unicast`")])

    @gen.command(name="ipv4", usage="")
    async def ipv4(self, ctx: commands.Context) -> None:
        """Generate a documentation-range IPv4 address."""
        await ack(ctx)
        value = _ipv4()
        await _emit(ctx, "ipv4", [("OUTPUT", f"`{value}`"), ("RANGE", "`RFC 5737 documentation`")])

    @gen.command(name="ipv6", usage="")
    async def ipv6(self, ctx: commands.Context) -> None:
        """Generate a documentation-range IPv6 address."""
        await ack(ctx)
        value = _ipv6()
        await _emit(ctx, "ipv6", [("OUTPUT", f"`{value}`"), ("RANGE", "`2001:db8::/32`")])

    @gen.command(name="domain", usage="")
    async def domain(self, ctx: commands.Context) -> None:
        """Generate a reserved example domain."""
        await ack(ctx)
        value = _domain()
        await _emit(ctx, "domain", [("OUTPUT", f"`{value}`"), ("TLD", "`.example`")])

    @gen.command(name="company", usage="")
    async def company(self, ctx: commands.Context) -> None:
        """Generate a fictional company name."""
        await ack(ctx)
        await _emit(ctx, "company", [("OUTPUT", f"`{_company()}`")])

    @gen.command(name="job", usage="")
    async def job(self, ctx: commands.Context) -> None:
        """Generate a fictional job title."""
        await ack(ctx)
        await _emit(ctx, "job", [("OUTPUT", f"`{_job()}`")])

    @gen.command(name="isbn", usage="")
    async def isbn(self, ctx: commands.Context) -> None:
        """Generate a valid synthetic ISBN-13."""
        await ack(ctx)
        value = _isbn()
        await _emit(ctx, "isbn", [("OUTPUT", f"`{value}`"), ("CHECK DIGIT", f"`{value[-1]}`")])

    @gen.command(name="otp", usage="")
    async def otp(self, ctx: commands.Context) -> None:
        """Generate a six-digit test code."""
        await ack(ctx)
        await _emit(ctx, "otp", [("OUTPUT", f"`{_otp()}`")], "For test fixtures only; do not use as an authentication factor.")

    @gen.command(name="apikey", usage="")
    async def apikey(self, ctx: commands.Context) -> None:
        """Generate a random test API token."""
        await ack(ctx)
        await _emit(ctx, "apikey", [("OUTPUT", f"`{_apikey()}`")], "Prefixed `osk_test_` so it is clearly not a production credential.")

    @gen.command(name="color", usage="")
    async def color(self, ctx: commands.Context) -> None:
        """Generate a random hex colour."""
        await ack(ctx)
        await _emit(ctx, "color", [("OUTPUT", f"`{_color()}`")])

    @gen.command(name="lorem", usage="")
    async def lorem(self, ctx: commands.Context) -> None:
        """Generate a short placeholder sentence."""
        await ack(ctx)
        await _emit(ctx, "lorem", [("OUTPUT", _lorem())])


async def setup(bot: Any) -> None:
    await bot.add_cog(Generator(bot))
