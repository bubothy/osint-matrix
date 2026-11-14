"""Social and developer platform intelligence from public profile APIs."""

from __future__ import annotations

import html as html_module
import re
import xml.etree.ElementTree as ElementTree
from typing import Any
from urllib.parse import quote

from discord.ext import commands

from config import settings
from core.command import intel
from core.embeds import Intel
from core.errors import IntelError, NotFound, SourceUnavailable, UsageError
from core.utils import ack, clip, fmt_dt, human_delta, num, parse_dt, require, utcnow


def strip_tags(value: str) -> str:
    return html_module.unescape(re.sub(r"<[^>]+>", " ", value or "")).strip()


def dashed_uuid(raw: str) -> str:
    raw = raw.replace("-", "")
    if len(raw) != 32:
        return raw
    return f"{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:]}"


class Social(commands.Cog, name="Social"):
    """Public profile lookups on developer, gaming and social platforms."""

    def __init__(self, bot: Any) -> None:
        self.bot = bot
        self.net = bot.net

    def _github_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "OSINT-MATRIX",
        }
        token = settings.key("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    @staticmethod
    def _handle(target: str | None, label: str, example: str) -> str:
        raw = require(target, label, example=example).strip().lstrip("@")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", raw):
            raise UsageError("That handle contains characters outside the platform's allowed set.")
        return raw

    # ── developer platforms ──────────────────────────────────────────────

    @intel(
        category="social",
        brief="GitHub profile: identity, company, location, activity, languages and star count.",
        usage="<username>",
        aliases=["gh"],
        examples=["github torvalds"],
        sources=["api.github.com"],
        cooldown=(3, 12),
    )
    async def github(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        user = self._handle(target, "GitHub username", ".github torvalds")
        try:
            profile = await self.net.get_json(
                f"https://api.github.com/users/{quote(user)}",
                headers=self._github_headers(),
                cache_ttl=600,
            )
        except IntelError as exc:
            if "403" in str(exc.detail):
                raise SourceUnavailable(
                    "GitHub rate-limited this instance.",
                    hint="Add a `GITHUB_TOKEN` to `.env` to raise the ceiling from 60 to 5,000 requests/hour.",
                ) from exc
            raise NotFound(f"GitHub has no user named `{user}`.") from None
        repos: list[dict[str, Any]] = []
        try:
            repos = await self.net.get_json(
                f"https://api.github.com/users/{quote(user)}/repos?per_page=100&sort=updated",
                headers=self._github_headers(),
                cache_ttl=600,
                expect=False,
            )
        except IntelError:
            repos = []
        if not isinstance(repos, list):
            repos = []
        stars = sum(int(repo.get("stargazers_count") or 0) for repo in repos)
        forks = sum(int(repo.get("forks_count") or 0) for repo in repos)
        languages: dict[str, int] = {}
        for repo in repos:
            language = repo.get("language")
            if language:
                languages[language] = languages.get(language, 0) + 1
        embed = Intel(
            category="social",
            command="github",
            ctx=ctx,
            target=profile.get("login", user),
            summary="Public developer identity. Repositories, stars and languages are derived from the account's visible work.",
        )
        embed.kv(
            "IDENTITY",
            {
                "Login": profile.get("login"),
                "Name": profile.get("name"),
                "Type": profile.get("type"),
                "Company": profile.get("company"),
                "Location": profile.get("location"),
                "Website": profile.get("blog"),
                "Twitter": profile.get("twitter_username"),
                "Hireable": profile.get("hireable"),
                "Bio": clip(profile.get("bio") or "", 180),
            },
            inline=True,
        )
        embed.kv(
            "FOOTPRINT",
            {
                "Public repos": profile.get("public_repos"),
                "Gists": profile.get("public_gists"),
                "Followers": num(profile.get("followers")),
                "Following": num(profile.get("following")),
                "Stars (page 1)": num(stars),
                "Forks (page 1)": num(forks),
            },
            inline=True,
        )
        embed.kv(
            "LIFECYCLE",
            {
                "Created": fmt_dt(profile.get("created_at")),
                "Updated": fmt_dt(profile.get("updated_at")),
                "Age": human_delta((utcnow() - parse_dt(profile.get("created_at"))).total_seconds()) if parse_dt(profile.get("created_at")) else "—",
                "Profile URL": profile.get("html_url"),
            },
            inline=True,
        )
        if languages:
            embed.kv("LANGUAGES", dict(sorted(languages.items(), key=lambda item: item[1], reverse=True)[:8]), inline=True)
        embed.thumbnail(profile.get("avatar_url"))
        embed.checks(
            "SIGNALS",
            [
                (bool(profile.get("name")), "Real name published", str(profile.get("name") or "not published")),
                (bool(profile.get("location")), "Location published", str(profile.get("location") or "not published")),
                (bool(profile.get("blog")), "External site", str(profile.get("blog") or "none")),
                (None, "Key", "configured GITHUB_TOKEN" if settings.has("GITHUB_TOKEN") else "unauthenticated (60 req/h)"),
            ],
        )
        embed.source("api.github.com")
        await embed.send(ctx)

    @intel(
        category="social",
        brief="Repository inventory for a GitHub account with language and popularity ranking.",
        usage="<username>",
        aliases=["repos"],
        examples=["ghrepos torvalds"],
        sources=["api.github.com"],
        cooldown=(3, 15),
    )
    async def ghrepos(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        user = self._handle(target, "GitHub username", ".ghrepos torvalds")
        try:
            repos = await self.net.get_json(
                f"https://api.github.com/users/{quote(user)}/repos?per_page=100&sort=updated",
                headers=self._github_headers(),
                cache_ttl=600,
                expect=False,
            )
        except IntelError:
            raise NotFound(f"Could not read repositories for `{user}`.") from None
        if not isinstance(repos, list) or not repos:
            raise NotFound(f"`{user}` has no public repositories.")
        ranked = sorted(repos, key=lambda repo: int(repo.get("stargazers_count") or 0), reverse=True)
        languages: dict[str, int] = {}
        for repo in repos:
            if repo.get("language"):
                languages[repo["language"]] = languages.get(repo["language"], 0) + 1
        embed = Intel(
            category="social",
            command="ghrepos",
            ctx=ctx,
            target=user,
            summary="Public repositories only. Archived and forked projects are counted separately so the signal stays honest.",
        )
        embed.kv(
            "INVENTORY",
            {
                "Repositories (page 1)": len(repos),
                "Total stars": num(sum(int(repo.get("stargazers_count") or 0) for repo in repos)),
                "Forks": sum(1 for repo in repos if repo.get("fork")),
                "Archived": sum(1 for repo in repos if repo.get("archived")),
                "Languages": len(languages),
            },
            inline=True,
        )
        embed.kv("LANGUAGE MIX", dict(sorted(languages.items(), key=lambda item: item[1], reverse=True)[:10]), inline=True)
        embed.table(
            "MOST STARRED",
            ["STARS", "REPO", "LANGUAGE"],
            [
                [num(repo.get("stargazers_count")), clip(repo.get("name", "?"), 32), clip(repo.get("language") or "-", 16)]
                for repo in ranked[:15]
            ],
        )
        embed.table(
            "RECENT ACTIVITY",
            ["PUSHED", "REPO", "DESCRIPTION"],
            [
                [
                    str(repo.get("pushed_at") or "")[:10],
                    clip(repo.get("name", "?"), 32),
                    clip(repo.get("description") or "-", 32),
                ]
                for repo in sorted(repos, key=lambda repo: str(repo.get("pushed_at") or ""), reverse=True)[:10]
            ],
        )
        embed.source("api.github.com")
        await embed.send(ctx)

    @intel(
        category="social",
        brief="GitLab account lookup by username.",
        usage="<username>",
        aliases=["gl"],
        examples=["gitlab gitlab-bot"],
        sources=["gitlab.com/api/v4"],
        cooldown=(3, 12),
    )
    async def gitlab(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        user = self._handle(target, "GitLab username", ".gitlab gitlab-bot")
        payload = await self.net.get_json(
            "https://gitlab.com/api/v4/users",
            params={"username": user},
            cache_ttl=600,
            expect=False,
        )
        if not payload:
            raise NotFound(f"GitLab has no active user named `{user}`.")
        profile = payload[0]
        embed = Intel(
            category="social",
            command="gitlab",
            ctx=ctx,
            target=profile.get("username", user),
            summary="GitLab exposes less than GitHub by default, but the state and creation date are still public.",
        )
        embed.kv(
            "ACCOUNT",
            {
                "ID": profile.get("id"),
                "Username": profile.get("username"),
                "Name": profile.get("name"),
                "State": profile.get("state"),
                "Created": fmt_dt(profile.get("created_at")),
                "Bot": profile.get("bot"),
                "Admin": profile.get("is_admin"),
            },
            inline=True,
        )
        embed.kv(
            "PROFILE",
            {
                "Bio": clip(profile.get("bio") or "", 180),
                "Location": profile.get("location"),
                "Public email": profile.get("public_email"),
                "Website": profile.get("website_url"),
                "LinkedIn": profile.get("linkedin"),
                "Twitter": profile.get("twitter"),
                "Organisation": profile.get("organization"),
            },
            inline=True,
        )
        embed.kv("URLS", {"Profile": profile.get("web_url"), "Avatar": profile.get("avatar_url")}, inline=False)
        embed.thumbnail(profile.get("avatar_url"))
        embed.source("gitlab.com/api/v4")
        await embed.send(ctx)

    @intel(
        category="social",
        brief="Reddit account: karma split, age, verification and moderator status.",
        usage="<username>",
        aliases=["reddituser"],
        examples=["reddit spez"],
        sources=["reddit.com JSON"],
        cooldown=(3, 12),
    )
    async def reddit(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        user = self._handle(target, "Reddit username", ".reddit spez")
        try:
            payload = await self.net.get_json(
                f"https://www.reddit.com/user/{quote(user)}/about.json",
                headers={"User-Agent": "OSINT-MATRIX/1.0 (private research)"},
                cache_ttl=600,
            )
        except IntelError as exc:
            raise SourceUnavailable(
                "Reddit refused the anonymous profile request.",
                hint="Reddit blocks data-centre IPs aggressively. Try again later or from a residential connection.",
            ) from exc
        data = payload.get("data") or {}
        if not data.get("name"):
            raise NotFound(f"Reddit has no user named `{user}`.")
        embed = Intel(
            category="social",
            command="reddit",
            ctx=ctx,
            target=data.get("name"),
            summary="Public Reddit profile. Karma splits reveal whether an account is primarily a commenter or a link submitter.",
        )
        embed.kv(
            "ACCOUNT",
            {
                "Username": data.get("name"),
                "ID": data.get("id"),
                "Created": fmt_dt(data.get("created_utc")),
                "Age": human_delta((utcnow() - parse_dt(data.get("created_utc"))).total_seconds()) if parse_dt(data.get("created_utc")) else "—",
                "Verified email": data.get("has_verified_email"),
                "Gold": data.get("is_gold"),
                "Moderator": data.get("is_mod"),
                "Employee": data.get("is_employee"),
            },
            inline=True,
        )
        embed.kv(
            "KARMA",
            {
                "Total": num(data.get("total_karma")),
                "Post": num(data.get("link_karma")),
                "Comment": num(data.get("comment_karma")),
                "Awarder": num(data.get("awarder_karma")),
                "Awardee": num(data.get("awardee_karma")),
            },
            inline=True,
        )
        embed.kv(
            "PRESENTATION",
            {
                "Title": data.get("subreddit", {}).get("title") if isinstance(data.get("subreddit"), dict) else None,
                "Public description": clip(strip_tags(data.get("subreddit", {}).get("public_description", "")) if isinstance(data.get("subreddit"), dict) else "", 180),
                "Profile image": bool(data.get("icon_img")),
                "Accepting PMs": data.get("accept_pms"),
                "URL": f"https://reddit.com/user/{data.get('name')}",
            },
            inline=False,
        )
        embed.thumbnail(data.get("icon_img") or None)
        embed.source("reddit.com")
        await embed.send(ctx)

    @intel(
        category="social",
        brief="Subreddit statistics: subscribers, creation date, classification and description.",
        usage="<subreddit>",
        aliases=["subreddit", "r"],
        examples=["redditsub osint"],
        sources=["reddit.com JSON"],
        cooldown=(3, 12),
    )
    async def redditsub(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        name = self._handle(target, "subreddit", ".redditsub osint")
        try:
            payload = await self.net.get_json(
                f"https://www.reddit.com/r/{quote(name)}/about.json",
                headers={"User-Agent": "OSINT-MATRIX/1.0 (private research)"},
                cache_ttl=600,
            )
        except IntelError as exc:
            raise SourceUnavailable("Reddit refused the anonymous request.") from exc
        data = payload.get("data") or {}
        if not data.get("display_name"):
            raise NotFound(f"Reddit has no subreddit named `r/{name}`.")
        embed = Intel(
            category="social",
            command="redditsub",
            ctx=ctx,
            target=f"r/{data.get('display_name')}",
            summary="Community-level metadata, useful for judging whether a claim originates from a large or a niche community.",
        )
        embed.kv(
            "COMMUNITY",
            {
                "Name": data.get("display_name"),
                "Title": data.get("title"),
                "Subscribers": num(data.get("subscribers")),
                "Active accounts": num(data.get("accounts_active")),
                "Created": fmt_dt(data.get("created_utc")),
                "Over 18": data.get("over18"),
                "Language": data.get("lang"),
                "Type": data.get("subreddit_type"),
            },
            inline=True,
        )
        embed.kv(
            "POLICY",
            {
                "NSFW": data.get("over18"),
                "Quarantined": data.get("quarantine"),
                "Submission type": data.get("submission_type"),
                "Spoilers": data.get("spoilers_enabled"),
                "Wiki": data.get("wiki_enabled"),
                "URL": f"https://reddit.com{data.get('url', '')}",
            },
            inline=True,
        )
        embed.text("DESCRIPTION", clip(data.get("public_description") or "none", 500), inline=False)
        embed.thumbnail(data.get("community_icon") or data.get("icon_img") or None)
        embed.source("reddit.com")
        await embed.send(ctx)

    @intel(
        category="social",
        brief="Hacker News account: karma, join date, submission count and about text.",
        usage="<username>",
        aliases=["hn"],
        examples=["hackernews pg"],
        sources=["hacker-news.firebaseio.com"],
        cooldown=(3, 10),
    )
    async def hackernews(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        user = self._handle(target, "Hacker News username", ".hackernews pg")
        payload = await self.net.get_json(
            f"https://hacker-news.firebaseio.com/v0/user/{quote(user)}.json",
            cache_ttl=600,
            expect=False,
        )
        if not payload:
            raise NotFound(f"Hacker News has no user named `{user}`.")
        embed = Intel(
            category="social",
            command="hackernews",
            ctx=ctx,
            target=payload.get("id", user),
            summary="Hacker News profiles are minimal by design: karma and join date are the only reliable signals.",
        )
        submitted = payload.get("submitted") or []
        embed.kv(
            "ACCOUNT",
            {
                "Username": payload.get("id"),
                "Karma": num(payload.get("karma")),
                "Created": fmt_dt(payload.get("created")),
                "Age": human_delta((utcnow() - parse_dt(payload.get("created"))).total_seconds()) if parse_dt(payload.get("created")) else "—",
                "Submissions": num(len(submitted)),
                "Profile": f"https://news.ycombinator.com/user?id={payload.get('id')}",
            },
            inline=True,
        )
        embed.text("ABOUT", clip(strip_tags(payload.get("about") or "nothing published"), 600), inline=False)
        embed.source("hacker-news.firebaseio.com")
        await embed.send(ctx)

    @intel(
        category="social",
        brief="dev.to author profile including linked GitHub and Twitter handles.",
        usage="<username>",
        name="devto",
        examples=["devto ben"],
        sources=["dev.to/api"],
        cooldown=(3, 12),
    )
    async def devto_cmd(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        user = self._handle(target, "dev.to username", ".devto ben")
        try:
            payload = await self.net.get_json(
                "https://dev.to/api/users/by_username",
                params={"url": user},
                cache_ttl=600,
            )
        except IntelError:
            raise NotFound(f"dev.to has no user named `{user}`.") from None
        embed = Intel(
            category="social",
            command="devto",
            ctx=ctx,
            target=payload.get("username", user),
            summary="Cross-links are the point here: a dev.to profile often reveals the same person's GitHub and Twitter handles.",
        )
        embed.kv(
            "PROFILE",
            {
                "Name": payload.get("name"),
                "Username": payload.get("username"),
                "Summary": clip(payload.get("summary") or "", 180),
                "Location": payload.get("location"),
                "Joined": fmt_dt(payload.get("joined_at")),
                "Website": payload.get("website_url"),
                "GitHub": payload.get("github_username"),
                "Twitter": payload.get("twitter_username"),
            },
            inline=True,
        )
        embed.kv(
            "ACTIVITY",
            {
                "Profile": f"https://dev.to/{payload.get('username')}",
                "Avatar": bool(payload.get("profile_image")),
                "ID": payload.get("id"),
            },
            inline=True,
        )
        embed.thumbnail(payload.get("profile_image"))
        embed.source("dev.to/api")
        await embed.send(ctx)

    @intel(
        category="social",
        brief="Stack Overflow reputation, badges and account age by numeric user ID.",
        usage="<user id>",
        name="stackoverflow",
        aliases=["so"],
        examples=["stackoverflow 1"],
        sources=["api.stackexchange.com"],
        cooldown=(3, 12),
    )
    async def stackoverflow_cmd(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "Stack Overflow user ID", example=".stackoverflow 1").strip()
        if not raw.isdigit():
            raise UsageError("Stack Exchange exposes users by numeric ID, not username.")
        payload = await self.net.get_json(
            f"https://api.stackexchange.com/2.3/users/{raw}",
            params={"site": "stackoverflow", "filter": "default"},
            cache_ttl=600,
            expect=False,
        )
        items = payload.get("items") or []
        if not items:
            raise NotFound(f"No Stack Overflow user with ID `{raw}`.")
        data = items[0]
        badges = data.get("badge_counts") or {}
        embed = Intel(
            category="social",
            command="stackoverflow",
            ctx=ctx,
            target=data.get("display_name", raw),
            summary="Stack Exchange profiles are strongly linked to real-world expertise and often list a personal site.",
            )
        embed.kv(
            "ACCOUNT",
            {
                "Display name": data.get("display_name"),
                "User ID": data.get("user_id"),
                "Reputation": num(data.get("reputation")),
                "Created": fmt_dt(data.get("creation_date")),
                "Last access": fmt_dt(data.get("last_access_date")),
                "Account type": data.get("account_id"),
            },
            inline=True,
        )
        embed.kv(
            "BADGES",
            {
                "Gold": badges.get("gold"),
                "Silver": badges.get("silver"),
                "Bronze": badges.get("bronze"),
                "Total": num(sum(int(value or 0) for value in badges.values())),
            },
            inline=True,
        )
        embed.kv(
            "LINKS",
            {
                "Location": data.get("location"),
                "Website": data.get("website_url"),
                "Profile": data.get("link"),
                "Accept rate": data.get("accept_rate"),
            },
            inline=False,
        )
        embed.thumbnail(data.get("profile_image"))
        embed.source("api.stackexchange.com")
        await embed.send(ctx)

    @intel(
        category="social",
        brief="npm maintainer footprint: package count, names and latest releases.",
        usage="<username>",
        aliases=["npmjs"],
        examples=["npm sindresorhus"],
        sources=["registry.npmjs.org"],
        cooldown=(3, 15),
    )
    async def npm(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        user = self._handle(target, "npm username", ".npm sindresorhus")
        payload = await self.net.get_json(
            "https://registry.npmjs.org/-/v1/search",
            params={"text": f"maintainer:{user}", "size": 25},
            cache_ttl=600,
            expect=False,
        )
        objects = payload.get("objects") or []
        total = int(payload.get("total") or 0)
        if not total and not objects:
            raise NotFound(f"npm has no packages maintained by `{user}`.")
        packages = [item.get("package") or {} for item in objects]
        embed = Intel(
            category="social",
            command="npm",
            ctx=ctx,
            target=user,
            summary="The npm registry is a public record of who publishes what — useful for attributing a package to an identity.",
        )
        embed.kv(
            "FOOTPRINT",
            {
                "Matching packages": num(total),
                "Shown": len(packages),
                "Scoped packages": sum(1 for package in packages if str(package.get("name", "")).startswith("@")),
                "Profile": f"https://www.npmjs.com/~{user}",
            },
            inline=True,
        )
        embed.code(
            "PACKAGES",
            "\n".join(
                f"{clip(package.get('name', '?'), 34):34}  {clip(package.get('version') or '-', 10):10}  {str(package.get('date') or '')[:10]}"
                for package in packages[:20]
            )
            or "no packages returned",
            lang="yaml",
        )
        embed.source("registry.npmjs.org")
        await embed.send(ctx)

    @intel(
        category="social",
        brief="PyPI package metadata: maintainer, project links, releases and classifiers.",
        usage="<package>",
        name="pypi",
        examples=["pypi requests"],
        sources=["pypi.org/pypi"],
        cooldown=(3, 12),
    )
    async def pypi_cmd(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        package = require(target, "package name", example=".pypi requests").strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", package):
            raise UsageError("That is not a valid package name.")
        try:
            payload = await self.net.get_json(f"https://pypi.org/pypi/{quote(package)}/json", cache_ttl=600)
        except IntelError:
            raise NotFound(f"PyPI has no package named `{package}`.") from None
        info = payload.get("info") or {}
        releases = payload.get("releases") or {}
        latest_files = releases.get(info.get("version"), []) or []
        embed = Intel(
            category="social",
            command="pypi",
            ctx=ctx,
            target=info.get("name", package),
            summary="Package metadata links a project to an author identity and often to a source repository.",
        )
        embed.kv(
            "PROJECT",
            {
                "Name": info.get("name"),
                "Version": info.get("version"),
                "Author": info.get("author"),
                "Author email": info.get("author_email"),
                "Maintainer": info.get("maintainer"),
                "License": clip(info.get("license") or "", 60),
                "Requires Python": info.get("requires_python"),
                "Releases": len(releases),
            },
            inline=True,
        )
        embed.kv(
            "LINKS",
            {
                "Home": info.get("home_page"),
                "Project URLs": info.get("project_urls"),
                "Summary": clip(info.get("summary") or "", 160),
            },
            inline=True,
        )
        embed.kv(
            "LATEST RELEASE",
            {
                "Uploaded": fmt_dt(latest_files[0].get("upload_time_iso_8601")) if latest_files else "no files",
                "Files": len(latest_files),
                "Size": num(sum(int(item.get("size") or 0) for item in latest_files)) + " bytes",
            },
            inline=True,
        )
        classifiers = [item for item in info.get("classifiers") or [] if item.startswith(("Programming Language", "License", "Development Status"))]
        if classifiers:
            embed.code("CLASSIFIERS", "\n".join(classifiers[:10]), lang="yaml")
        embed.source("pypi.org")
        await embed.send(ctx)

    # ── gaming / messaging ───────────────────────────────────────────────

    @intel(
        category="social",
        brief="Steam profile: SteamID, bans, member since, location and top games.",
        usage="<vanity|steamid64>",
        aliases=["steamid"],
        examples=["steam gabe_logan"],
        sources=["steamcommunity.com XML", "Steam Web API (optional key)"],
        cooldown=(3, 15),
    )
    async def steam(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "Steam vanity or SteamID64", example=".steam gabe_logan").strip()
        url = f"https://steamcommunity.com/profiles/{raw}/?xml=1" if raw.isdigit() else f"https://steamcommunity.com/id/{quote(raw)}/?xml=1"
        response = await self.net.get(url, cache_ttl=600, timeout=15)
        if not response.ok:
            raise NotFound(f"Steam returned HTTP {response.status} for `{raw}`.")
        try:
            root = ElementTree.fromstring(response.text)
        except ElementTree.ParseError:
            raise SourceUnavailable("Steam returned a malformed profile document.") from None
        if root.findtext("error"):
            raise NotFound(f"Steam has no profile for `{raw}`.")

        def text(tag: str) -> str:
            return (root.findtext(tag) or "").strip()

        steam_id = text("steamID64")
        embed = Intel(
            category="social",
            command="steam",
            ctx=ctx,
            target=text("steamID") or raw,
            summary="Steam exposes this XML feed without authentication. Private profiles still reveal the account age and ID.",
        )
        embed.kv(
            "ACCOUNT",
            {
                "SteamID64": steam_id,
                "SteamID": text("steamID"),
                "Online state": text("onlineState"),
                "Privacy": text("privacyState"),
                "Member since": text("memberSince"),
                "Limited account": text("isLimitedAccount"),
                "Vac banned": text("vacBanned"),
                "Trade ban": text("tradeBanState"),
            },
            inline=True,
        )
        embed.kv(
            "PROFILE",
            {
                "Real name": text("realname"),
                "Location": text("location"),
                "Summary": clip(strip_tags(text("summary")), 200),
                "Custom URL": text("customURL"),
                "Avatar": bool(text("avatarFull")),
                "Profile": f"https://steamcommunity.com/profiles/{steam_id}" if steam_id else "unknown",
            },
            inline=True,
        )
        games = root.find("mostPlayedGames")
        if games is not None:
            rows = []
            for game in games.findall("mostPlayedGame")[:6]:
                rows.append(
                    f"{clip(game.findtext('gameName') or '?', 34):34} {game.findtext('hoursOnRecord') or '?':>8}h  {game.findtext('hoursLast2Weeks') or '?':>6}h/2w"
                )
            if rows:
                embed.code("MOST PLAYED", "\n".join(rows), lang="yaml")
        embed.thumbnail(text("avatarFull") or None)
        embed.checks(
            "SIGNALS",
            [
                (text("privacyState") == "public", "Public profile", text("privacyState") or "unknown"),
                (text("vacBanned") == "0", "No VAC ban", text("vacBanned") or "unknown"),
                (bool(text("location")), "Location shared", text("location") or "not shared"),
                (None, "ID", "SteamID64 is a permanent account identifier"),
            ],
        )
        embed.source("steamcommunity.com")
        await embed.send(ctx)

    @intel(
        category="social",
        brief="Minecraft account: UUID, skin, cape and name history via Mojang.",
        usage="<username>",
        aliases=["mc", "mojang"],
        examples=["minecraft Notch"],
        sources=["api.mojang.com", "sessionserver.mojang.com"],
        cooldown=(3, 12),
    )
    async def minecraft(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        name = self._handle(target, "Minecraft username", ".minecraft Notch")
        try:
            profile = await self.net.get_json(
                f"https://api.mojang.com/users/profiles/minecraft/{quote(name)}", cache_ttl=900
            )
        except IntelError:
            raise NotFound(f"Mojang has no account named `{name}` (or the name is not an original Java account).") from None
        raw_uuid = str(profile.get("id", ""))
        uuid_value = dashed_uuid(raw_uuid)
        session: dict[str, Any] = {}
        try:
            session = await self.net.get_json(
                f"https://sessionserver.mojang.com/session/minecraft/profile/{raw_uuid}", cache_ttl=900
            )
        except IntelError:
            session = {}
        textures = {}
        for prop in session.get("properties") or []:
            if prop.get("name") == "textures":
                import base64 as _b64
                import json as _json

                try:
                    textures = _json.loads(_b64.b64decode(prop.get("value", "")).decode())
                except Exception:  # noqa: BLE001 - cosmetic decode
                    textures = {}
        skin = (((textures.get("textures") or {}).get("SKIN") or {}).get("url")) or f"https://crafatar.com/skins/{uuid_value}"
        cape = ((textures.get("textures") or {}).get("CAPE") or {}).get("url")
        embed = Intel(
            category="social",
            command="minecraft",
            ctx=ctx,
            target=profile.get("name", name),
            summary="Mojang's public API maps a Java username to a permanent UUID and the skin currently attached to it.",
        )
        embed.kv(
            "ACCOUNT",
            {
                "Username": profile.get("name"),
                "UUID (compact)": raw_uuid,
                "UUID (dashed)": uuid_value,
                "Model": session.get("profileName") and "legacy or modern" or "unknown",
                "Skin": "published" if skin else "not published",
                "Cape": "published" if cape else "none",
            },
            inline=True,
        )
        embed.kv(
            "ASSETS",
            {
                "Skin": skin,
                "Cape": cape or "none",
                "Render": f"https://crafatar.com/renders/body/{uuid_value}?overlay",
                "Avatar": f"https://crafatar.com/avatars/{uuid_value}?size=128",
                "NameMC": f"https://namemc.com/profile/{uuid_value}",
            },
            inline=False,
        )
        embed.image(skin)
        embed.steps(
            [
                "Resolved the username to a Mojang UUID",
                "Requested the session profile for signed texture metadata",
                "Decoded the base64 texture blob for skin and cape URLs",
            ]
        )
        embed.source("api.mojang.com", "sessionserver.mojang.com")
        await embed.send(ctx)

    @intel(
        category="social",
        brief="Roblox account: ID, creation date, verification, ban state and avatar.",
        usage="<username>",
        aliases=["rbx"],
        examples=["roblox Roblox"],
        sources=["users.roblox.com", "thumbnails.roblox.com"],
        cooldown=(3, 12),
    )
    async def roblox(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        user = self._handle(target, "Roblox username", ".roblox Roblox")
        search = await self.net.request(
            "POST",
            "https://users.roblox.com/v1/usernames/users",
            json_body={"usernames": [user], "excludeBannedUsers": False},
            cache_ttl=600,
        )
        if not search.ok:
            raise SourceUnavailable(f"Roblox answered HTTP {search.status}.")
        data = (search.json() or {}).get("data") or []
        if not data:
            raise NotFound(f"Roblox has no account named `{user}`.")
        entry = data[0]
        user_id = entry.get("id")
        detail: dict[str, Any] = {}
        try:
            detail = await self.net.get_json(f"https://users.roblox.com/v1/users/{user_id}", cache_ttl=600)
        except IntelError:
            detail = entry
        embed = Intel(
            category="social",
            command="roblox",
            ctx=ctx,
            target=entry.get("name", user),
            summary="Roblox returns account creation dates and display names without authentication.",
        )
        embed.kv(
            "ACCOUNT",
            {
                "Username": entry.get("name"),
                "Display name": entry.get("displayName"),
                "User ID": user_id,
                "Created": fmt_dt(detail.get("created")),
                "Age": human_delta((utcnow() - parse_dt(detail.get("created"))).total_seconds()) if parse_dt(detail.get("created")) else "—",
                "Verified badge": detail.get("hasVerifiedBadge"),
                "Banned": detail.get("isBanned"),
            },
            inline=True,
        )
        embed.text("DESCRIPTION", clip(detail.get("description") or "no description", 500), inline=False)
        headshot = None
        avatar = None
        try:
            assets = await self.net.get_json(
                "https://thumbnails.roblox.com/v1/users/avatar-headshot",
                params={"userIds": user_id, "size": "420x420", "format": "Png"},
                cache_ttl=600,
            )
            rows = assets.get("data") or []
            if rows:
                headshot = rows[0].get("imageUrl")
            assets = await self.net.get_json(
                "https://thumbnails.roblox.com/v1/users/avatar",
                params={"userIds": user_id, "size": "420x420", "format": "Png"},
                cache_ttl=600,
            )
            rows = assets.get("data") or []
            if rows:
                avatar = rows[0].get("imageUrl")
        except IntelError:
            pass
        embed.kv(
            "ASSETS",
            {
                "Profile": f"https://www.roblox.com/users/{user_id}/profile",
                "Headshot": headshot or "unavailable",
                "Avatar": avatar or "unavailable",
            },
            inline=False,
        )
        if headshot:
            embed.thumbnail(headshot)
        embed.source("users.roblox.com")
        await embed.send(ctx)

    @intel(
        category="social",
        brief="Telegram public channel or user preview: title, bio and member count.",
        usage="<handle>",
        aliases=["tg"],
        examples=["telegram telegram"],
        sources=["t.me preview"],
        cooldown=(3, 12),
    )
    async def telegram(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        handle = self._handle(target, "Telegram handle", ".telegram telegram")
        response = await self.net.get(f"https://t.me/{quote(handle)}", cache_ttl=600, timeout=15)
        if not response.ok:
            raise NotFound(f"Telegram returned HTTP {response.status} for `@{handle}`.")
        page = response.text
        title = re.search(r'<meta property="og:title" content="([^"]*)"', page)
        description = re.search(r'<meta property="og:description" content="([^"]*)"', page)
        extra = re.search(r'tgme_page_extra">([^<]+)<', page)
        image = re.search(r'<meta property="og:image" content="([^"]*)"', page)
        if not title or not title.group(1):
            raise NotFound(f"No public Telegram page at `@{handle}`.")
        embed = Intel(
            category="social",
            command="telegram",
            ctx=ctx,
            target=f"@{handle}",
            summary="Only the public t.me preview is read. Private chats, groups and member lists are inaccessible.",
        )
        embed.kv(
            "PREVIEW",
            {
                "Title": html_module.unescape(title.group(1)),
                "Bio": clip(html_module.unescape(description.group(1)) if description else "none", 300),
                "Members": extra.group(1).strip() if extra else "not public",
                "Handle": f"@{handle}",
                "URL": f"https://t.me/{handle}",
            },
            inline=False,
        )
        embed.thumbnail(html_module.unescape(image.group(1)) if image else None)
        embed.checks(
            "SIGNALS",
            [
                (bool(extra), "Member count", extra.group(1).strip() if extra else "hidden"),
                (bool(description), "Description", "published" if description else "none"),
                (None, "Limit", "Telegram exposes no owner or creation date publicly"),
            ],
        )
        embed.source("t.me")
        await embed.send(ctx)

    @intel(
        category="social",
        brief="Keybase identity graph: proofs, devices and profile.",
        usage="<username>",
        aliases=["kb"],
        examples=["keybase max"],
        sources=["keybase.io API"],
        cooldown=(3, 12),
    )
    async def keybase(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        user = self._handle(target, "Keybase username", ".keybase max")
        payload = await self.net.get_json(
            "https://keybase.io/_/api/1.0/user/lookup.json",
            params={"username": user, "fields": "basics,profile,proofs,devices"},
            cache_ttl=600,
            expect=False,
        )
        them = (payload.get("them") or [])
        if not them:
            raise NotFound(f"Keybase has no user named `{user}`.")
        profile = them[0]
        basics = profile.get("basics") or {}
        proofs = (profile.get("proofs") or {}).get("all") or []
        devices = profile.get("devices") or []
        embed = Intel(
            category="social",
            command="keybase",
            ctx=ctx,
            target=basics.get("username", user),
            summary="Keybase is a cryptographic identity graph: every proof is a signed link to another account.",
        )
        embed.kv(
            "IDENTITY",
            {
                "Username": basics.get("username"),
                "UID": basics.get("uid"),
                "Full name": profile.get("profile", {}).get("full_name"),
                "Location": profile.get("profile", {}).get("location"),
                "Bio": clip(profile.get("profile", {}).get("bio") or "", 200),
                "Created": fmt_dt(basics.get("ctime")),
                "Devices": len(devices),
                "Proofs": len(proofs),
            },
            inline=True,
        )
        embed.code(
            "PROOFS",
            "\n".join(
                f"{clip(str(proof.get('proof_type') or '?'), 12):12} {clip(str(proof.get('nametag') or proof.get('username') or proof.get('hostname') or ''), 40)}"
                for proof in proofs[:14]
            )
            or "no proofs published",
            lang="yaml",
        )
        embed.source("keybase.io")
        await embed.send(ctx)

    # ── federated / decentralised ────────────────────────────────────────

    @intel(
        category="social",
        brief="Mastodon account lookup on any instance: followers, join date and bio.",
        usage="<user@instance>",
        aliases=["fediverse"],
        examples=["mastodon Gargron@mastodon.social"],
        sources=["per-instance Mastodon API"],
        cooldown=(3, 12),
    )
    async def mastodon(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "handle", example=".mastodon Gargron@mastodon.social").strip().lstrip("@")
        if "@" not in raw:
            raise UsageError("Use the federated form `user@instance.tld`.")
        user, _, instance = raw.partition("@")
        if not re.fullmatch(r"[A-Za-z0-9.-]+", instance):
            raise UsageError("That instance name is not valid.")
        payload = await self.net.get_json(
            f"https://{instance}/api/v1/accounts/lookup",
            params={"acct": user},
            cache_ttl=600,
            expect=False,
        )
        if not payload or not payload.get("id"):
            raise NotFound(f"`{raw}` has no public Mastodon account.")
        embed = Intel(
            category="social",
            command="mastodon",
            ctx=ctx,
            target=f"@{payload.get('acct')}@{instance}",
            summary="Each instance exposes its own public API. This lookup talks directly to the instance you name.",
        )
        embed.kv(
            "ACCOUNT",
            {
                "Username": payload.get("username"),
                "Acct": payload.get("acct"),
                "Display name": payload.get("display_name"),
                "Created": fmt_dt(payload.get("created_at")),
                "Followers": num(payload.get("followers_count")),
                "Following": num(payload.get("following_count")),
                "Statuses": num(payload.get("statuses_count")),
                "Bot": payload.get("bot"),
                "Locked": payload.get("locked"),
            },
            inline=True,
        )
        embed.text("BIO", clip(strip_tags(payload.get("note") or ""), 400), inline=False)
        embed.kv(
            "FIELDS",
            {str(field.get("name")): clip(strip_tags(field.get("value") or ""), 90) for field in (payload.get("fields") or [])[:6]} or {"note": "none"},
            inline=False,
        )
        embed.thumbnail(payload.get("avatar"))
        embed.source(instance)
        await embed.send(ctx)

    @intel(
        category="social",
        brief="Bluesky / AT Protocol profile: handle, DID, follow counts and labels.",
        usage="<handle|did>",
        aliases=["bsky"],
        examples=["bluesky bsky.app"],
        sources=["public.api.bsky.app"],
        cooldown=(3, 12),
    )
    async def bluesky(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "Bluesky handle", example=".bluesky bsky.app").strip().lstrip("@")
        actor = raw
        if not raw.startswith("did:"):
            resolved = await self.net.get_json(
                "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle",
                params={"handle": raw},
                cache_ttl=600,
                expect=False,
            )
            actor = (resolved or {}).get("did") or raw
        try:
            payload = await self.net.get_json(
                "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile",
                params={"actor": actor},
                cache_ttl=600,
            )
        except IntelError:
            raise NotFound(f"Bluesky has no profile for `{raw}`.") from None
        labels = [label.get("val") for label in (payload.get("labels") or []) if label.get("val")]
        embed = Intel(
            category="social",
            command="bluesky",
            ctx=ctx,
            target=payload.get("handle", raw),
            summary="AT Protocol identities are portable DIDs. The handle can change, the DID cannot.",
        )
        embed.kv(
            "IDENTITY",
            {
                "Handle": payload.get("handle"),
                "DID": payload.get("did"),
                "Display name": payload.get("displayName"),
                "Created": fmt_dt(payload.get("createdAt")),
                "Followers": num(payload.get("followersCount")),
                "Following": num(payload.get("followsCount")),
                "Posts": num(payload.get("postsCount")),
                "Labels": labels or "none applied",
            },
            inline=True,
        )
        embed.text("BIO", clip(payload.get("description") or "no description", 400), inline=False)
        embed.kv(
            "PRESENTATION",
            {
                "Profile": f"https://bsky.app/profile/{payload.get('handle')}",
                "Avatar": bool(payload.get("avatar")),
                "Banner": bool(payload.get("banner")),
                "Website": (payload.get("associated") or {}).get("website") if isinstance(payload.get("associated"), dict) else None,
            },
            inline=False,
        )
        embed.thumbnail(payload.get("avatar"))
        embed.source("public.api.bsky.app")
        await embed.send(ctx)


async def setup(bot: Any) -> None:
    await bot.add_cog(Social(bot))
