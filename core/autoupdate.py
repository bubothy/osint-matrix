"""Live deployment watcher for the Wispbyte container.

The panel only pulls a repository when the server starts. This task keeps the
running bot current: it polls the configured branch with ``git ls-remote`` and,
when the branch tip changes, clones that commit, checks that the Python tree
compiles, installs any new requirements, copies the source over the project and
re-execs the interpreter.

Only source files from the checkout are copied. ``.env``, ``data/``, ``logs/``,
``.local/`` and ``.cache/`` are removed from the temporary checkout first, so the
live Discord token, allow-list and logs survive every update.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

LOG = logging.getLogger("osint.autoupdate")

_SHA = re.compile(r"^[0-9a-f]{40}$")
_PYTHON = sys.executable
_DEPLOY_ROOT = Path("/home/container")


class UpdateError(RuntimeError):
    """A deployment step failed; keep the running process in place."""


def _env_flag(name: str) -> bool | None:
    """Read a boolean variable, returning ``None`` when it is unset."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return None
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int, *, low: int, high: int) -> int:
    try:
        value = int(str(os.getenv(name, "")).strip())
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


def _short(sha: str) -> str:
    return sha[:12] if sha else "unknown"


def _tail(data: bytes, limit: int = 1_500) -> str:
    text = data.decode("utf-8", errors="replace").strip()
    return text[-limit:] if len(text) > limit else text


@dataclass(frozen=True)
class UpdateConfig:
    """Resolved watcher settings."""

    enabled: bool
    repo: str
    branch: str
    interval: int
    root: Path
    state_file: Path

    @classmethod
    def from_environment(cls, root: Path, data_dir: Path) -> "UpdateConfig":
        root = Path(root).resolve()
        # AUTO_UPDATE_WATCH is the explicit switch (it also allows opt-in
        # outside Wispbyte). On Wispbyte the panel's AUTO_UPDATE variable is
        # already "1"; requiring the known container root keeps a local run
        # from being overwritten by the watcher.
        explicit = _env_flag("AUTO_UPDATE_WATCH")
        panel = _env_flag("AUTO_UPDATE")
        enabled = bool(explicit) if explicit is not None else bool(panel) and root == _DEPLOY_ROOT
        repo = (
            os.getenv("AUTO_UPDATE_REPO", "").strip()
            or os.getenv("GIT_ADDRESS", "").strip()
        )
        branch = (
            os.getenv("AUTO_UPDATE_BRANCH", "").strip()
            or os.getenv("BRANCH", "").strip()
            or "main"
        )
        return cls(
            enabled=enabled and bool(repo),
            repo=repo,
            branch=branch,
            interval=_env_int("AUTO_UPDATE_INTERVAL", 60, low=30, high=3_600),
            root=root,
            state_file=Path(data_dir) / "autoupdate_sha",
        )


class AutoUpdater:
    """Poll the deployment branch and restart into new commits."""

    def __init__(self, bot: Any, config: UpdateConfig | None = None) -> None:
        from config import DATA_DIR

        self.bot = bot
        self.config = config or UpdateConfig.from_environment(
            Path(__file__).resolve().parents[1], DATA_DIR
        )
        self._task: asyncio.Task[None] | None = None
        self._last_error = ""

    # ── lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        config = self.config
        if not config.enabled:
            LOG.info(
                "auto-update: watcher disabled (set AUTO_UPDATE_WATCH=1, or "
                "AUTO_UPDATE=1 under /home/container, with GIT_ADDRESS and BRANCH)"
            )
            return
        if self._task is not None and not self._task.done():
            return
        LOG.info(
            "auto-update: watching %s (%s) every %ss",
            config.repo,
            config.branch,
            config.interval,
        )
        self._task = asyncio.create_task(self._run(), name="osint-auto-update")

    async def stop(self) -> None:
        task = self._task
        self._task = None
        if task is None or task.done():
            return
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def _run(self) -> None:
        try:
            await self.bot.wait_until_ready()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a watcher must never stop the bot
            LOG.exception("auto-update: could not wait for Discord readiness")
            return
        deployed = self._read_state()
        LOG.info("auto-update: watcher active (deployed %s)", _short(deployed))
        while not self.bot.is_closed():
            try:
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - retry next interval
                message = f"{exc.__class__.__name__}: {exc}"
                if message != self._last_error:
                    LOG.warning("auto-update: check failed: %s", message)
                    self._last_error = message
            else:
                self._last_error = ""
            await asyncio.sleep(self.config.interval)

    async def _tick(self) -> None:
        remote = await self._remote_sha()
        deployed = self._read_state()
        if not deployed:
            # The startup command deploys the branch before the bot launches.
            # If no state file exists yet, use the current remote tip as the
            # baseline instead of restarting the process immediately.
            self._write_state(remote)
            LOG.info("auto-update: baseline set to %s", _short(remote))
            return
        if remote == deployed:
            return

        LOG.warning(
            "auto-update: new commit %s (deployed %s); deploying",
            _short(remote),
            _short(deployed),
        )
        if not await self._deploy(remote):
            return
        try:
            self._write_state(remote)
        except OSError as exc:
            LOG.error("auto-update: could not record deployed commit: %s", exc)
            return
        try:
            self._restart(remote)
        except OSError:
            LOG.exception("auto-update: could not re-exec the bot")
            try:
                self._write_state(deployed)
            except OSError:
                pass

    # ── git helpers ──────────────────────────────────────────────────────

    def _git_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        return env

    async def _git(self, *args: str, timeout: float = 60.0) -> str:
        # Wispbyte leaves a 63-byte .git worktree pointer in the project root.
        # Running git there makes even ``ls-remote`` try to open that stale
        # worktree, so every command runs from a neutral directory instead.
        cwd = tempfile.gettempdir()
        process = await asyncio.create_subprocess_exec(
            "git",
            *args,
            cwd=cwd,
            env=self._git_env(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError as exc:
            process.kill()
            await process.communicate()
            raise UpdateError(f"git timed out after {timeout:.0f}s") from exc
        if process.returncode != 0:
            detail = _tail(stderr) or _tail(stdout) or "no output"
            raise UpdateError(f"git exited {process.returncode}: {detail}")
        return stdout.decode("utf-8", errors="replace").strip()

    async def _remote_sha(self) -> str:
        output = await self._git(
            "ls-remote",
            self.config.repo,
            f"refs/heads/{self.config.branch}",
            timeout=30.0,
        )
        for line in output.splitlines():
            parts = line.split()
            if parts and _SHA.match(parts[0]):
                return parts[0]
        raise UpdateError(
            f"branch {self.config.branch!r} was not found in {self.config.repo}"
        )

    # ── deployment ───────────────────────────────────────────────────────

    async def _deploy(self, expected: str) -> bool:
        temp = Path(tempfile.mkdtemp(prefix="osint-autoupdate-"))
        source = temp / "src"
        try:
            try:
                await self._git(
                    "clone",
                    "--depth",
                    "1",
                    "--branch",
                    self.config.branch,
                    "--single-branch",
                    self.config.repo,
                    str(source),
                    timeout=180.0,
                )
            except UpdateError as exc:
                LOG.warning("auto-update: clone failed: %s", exc)
                return False

            actual = await self._git("-C", str(source), "rev-parse", "HEAD", timeout=15.0)
            if actual != expected:
                LOG.warning(
                    "auto-update: branch moved during clone (%s -> %s); retrying",
                    _short(expected),
                    _short(actual),
                )
                return False

            self._prepare(source)
            await self._compile(source, temp)
            await self._install_requirements(source)
            self._copy_tree(source)
            LOG.warning("auto-update: copied %s into %s", _short(expected), self.config.root)
            return True
        except UpdateError as exc:
            LOG.error("auto-update: deploy rejected: %s", exc)
            return False
        finally:
            shutil.rmtree(temp, ignore_errors=True)

    def _prepare(self, source: Path) -> None:
        """Remove live state and VCS metadata from a fresh checkout."""
        for name in (".git", ".env", ".local", ".cache", "data", "logs"):
            path = source / name
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            elif path.exists() or path.is_symlink():
                path.unlink()
        for cache in source.rglob("__pycache__"):
            shutil.rmtree(cache, ignore_errors=True)
        for bytecode in source.rglob("*.pyc"):
            try:
                bytecode.unlink()
            except OSError:
                pass

        missing = [name for name in ("bot.py", "requirements.txt") if not (source / name).is_file()]
        if missing:
            raise UpdateError("checkout is missing " + ", ".join(missing))

    async def _compile(self, source: Path, temp: Path) -> None:
        env = os.environ.copy()
        env["PYTHONPYCACHEPREFIX"] = str(temp / "pycache")
        process = await asyncio.create_subprocess_exec(
            _PYTHON,
            "-m",
            "compileall",
            "-q",
            str(source),
            cwd=str(source),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            output, _ = await asyncio.wait_for(process.communicate(), timeout=120.0)
        except asyncio.TimeoutError as exc:
            process.kill()
            await process.communicate()
            raise UpdateError("compile check timed out") from exc
        if process.returncode != 0:
            raise UpdateError("compile check failed: " + (_tail(output) or "no output"))

    async def _install_requirements(self, source: Path) -> None:
        process = await asyncio.create_subprocess_exec(
            _PYTHON,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "-U",
            "--prefix",
            str(self.config.root / ".local"),
            "-r",
            str(source / "requirements.txt"),
            cwd=str(self.config.root),
            env=os.environ.copy(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            output, _ = await asyncio.wait_for(process.communicate(), timeout=300.0)
        except asyncio.TimeoutError as exc:
            process.kill()
            await process.communicate()
            raise UpdateError("dependency install timed out") from exc
        if process.returncode != 0:
            raise UpdateError(
                "dependency install failed: " + (_tail(output) or "no output")
            )

    def _copy_tree(self, source: Path) -> None:
        destination = self.config.root
        for child in source.iterdir():
            target = destination / child.name
            if child.is_dir():
                shutil.copytree(
                    child,
                    target,
                    dirs_exist_ok=True,
                    symlinks=True,
                )
            else:
                shutil.copy2(child, target)

    # ── state and restart ────────────────────────────────────────────────

    def _read_state(self) -> str:
        try:
            value = self.config.state_file.read_text(encoding="utf-8").strip()
        except OSError:
            return ""
        return value if _SHA.match(value) else ""

    def _write_state(self, sha: str) -> None:
        self.config.state_file.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.config.state_file.with_name(self.config.state_file.name + ".tmp")
        temporary.write_text(sha + "\n", encoding="utf-8")
        os.replace(temporary, self.config.state_file)

    def _restart(self, sha: str) -> None:
        LOG.warning("auto-update: restarting into %s", _short(sha))
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:  # noqa: BLE001 - flushing is best effort
            pass
        logging.shutdown()
        os.chdir(self.config.root)
        os.execv(_PYTHON, [_PYTHON, str(self.config.root / "bot.py")])
