"""Interactive Components V2 views: pagination and confirmation."""

from __future__ import annotations

from typing import Sequence

import discord
from discord import ui

from core import v2


class Paginator(ui.LayoutView):
    """A five-control V2 paginator bound to the invoking user."""

    def __init__(
        self,
        pages: Sequence[discord.Embed],
        *,
        author_id: int | None = None,
        timeout: float = 240,
        files: Sequence[discord.File] = (),
    ) -> None:
        super().__init__(timeout=timeout)
        self.pages = list(pages) or [
            discord.Embed(description="No results to display.")
        ]
        self.author_id = author_id
        self.files = list(files)
        self.index = 0
        self.message: discord.Message | None = None
        self.closed = False
        self._build()

    # ── rendering ────────────────────────────────────────────────────────

    def _page(self) -> discord.Embed:
        page = self.pages[self.index]
        if len(self.pages) > 1:
            page = page.copy()
            try:
                existing = page.footer.text or ""
            except Exception:  # noqa: BLE001
                existing = ""
            if "part " not in existing and "page " not in existing:
                marker = f"page {self.index + 1}/{len(self.pages)}"
                page.set_footer(
                    text=((existing + "  •  " + marker) if existing else marker)[:2048]
                )
        return page

    def _button(
        self,
        label: str,
        action: str,
        *,
        disabled: bool = False,
        style: discord.ButtonStyle = discord.ButtonStyle.secondary,
    ) -> ui.Button:
        button = ui.Button(
            label=label,
            style=style,
            disabled=disabled,
            custom_id=f"v2:{id(self)}:{action}",
        )
        button.callback = getattr(self, f"_on_{action}")
        return button

    def _page_label(self, index: int | None = None) -> str:
        """A short page title used by the jump menu."""
        page = self.pages[self.index if index is None else index]
        try:
            title = str(page.title or "").strip()
        except Exception:  # noqa: BLE001 - cosmetic only
            title = ""
        if title:
            return title.split("  ·  ")[0][:60] or "result"
        try:
            description = str(page.description or "")
        except Exception:  # noqa: BLE001 - cosmetic only
            description = ""
        for line in reversed(description.splitlines()):
            if "sections" in line:
                return line.replace("-#", "").strip()[:60]
        return "result"

    def _jump_options(self) -> list[discord.SelectOption]:
        options: list[discord.SelectOption] = []
        for index in range(len(self.pages)):
            options.append(
                discord.SelectOption(
                    label=f"{index + 1:02d} · {self._page_label(index)}"[:100],
                    value=str(index),
                    default=index == self.index,
                )
            )
        return options

    def _build(self) -> None:
        self.clear_items()
        for item in v2.page_items(self._page(), files=self.files):
            self.add_item(item)

        total = len(self.pages)
        edge = self.closed
        row = ui.ActionRow()
        row.add_item(self._button("«", "first", disabled=edge or self.index == 0))
        row.add_item(self._button("‹", "previous", disabled=edge or self.index == 0))
        row.add_item(self._button(f"{self.index + 1}/{total}", "counter", disabled=True))
        row.add_item(self._button("›", "next", disabled=edge or self.index >= total - 1))
        row.add_item(self._button("»", "last", disabled=edge or self.index >= total - 1))
        self.add_item(row)

        if 4 < total <= 25:
            select = ui.Select(
                placeholder="Jump to section",
                options=self._jump_options(),
                min_values=1,
                max_values=1,
                custom_id=f"v2:{id(self)}:jump",
                disabled=edge,
            )
            select.callback = self._on_jump
            self.add_item(ui.ActionRow(select))

    # ── guards ───────────────────────────────────────────────────────────

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if self.author_id is not None and interaction.user.id != self.author_id:
            await interaction.response.send_message(
                "This result belongs to someone else. Run the command yourself.",
                ephemeral=True,
            )
            return False
        return True

    async def _update(self, interaction: discord.Interaction) -> None:
        self._build()
        await interaction.response.edit_message(view=self)

    async def _on_first(self, interaction: discord.Interaction) -> None:
        self.index = 0
        await self._update(interaction)

    async def _on_previous(self, interaction: discord.Interaction) -> None:
        self.index = max(0, self.index - 1)
        await self._update(interaction)

    async def _on_counter(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer()

    async def _on_next(self, interaction: discord.Interaction) -> None:
        self.index = min(len(self.pages) - 1, self.index + 1)
        await self._update(interaction)

    async def _on_last(self, interaction: discord.Interaction) -> None:
        self.index = len(self.pages) - 1
        await self._update(interaction)

    async def _on_jump(self, interaction: discord.Interaction) -> None:
        values = getattr(interaction, "data", {}) or {}
        raw = (values.get("values") or ["0"])[0]
        try:
            self.index = max(0, min(len(self.pages) - 1, int(raw)))
        except (TypeError, ValueError):
            await interaction.response.defer()
            return
        await self._update(interaction)

    async def on_timeout(self) -> None:
        self.closed = True
        try:
            self._build()
        except Exception:  # noqa: BLE001 - timeout cleanup is best effort
            pass
        if self.message is not None:
            try:
                await self.message.edit(view=self)
            except discord.HTTPException:
                pass


class Confirm(ui.LayoutView):
    """A two-button confirmation that uses the same V2 renderer."""

    def __init__(
        self,
        *,
        author_id: int,
        confirm_label: str = "Confirm",
        prompt: discord.Embed | None = None,
        timeout: float = 60,
    ) -> None:
        super().__init__(timeout=timeout)
        self.author_id = author_id
        self.confirm_label = confirm_label
        self.prompt = prompt or discord.Embed(
            description="This action cannot be undone."
        )
        self.value: bool | None = None
        self.message: discord.Message | None = None
        self._build()

    def _build(self) -> None:
        self.clear_items()
        for item in v2.page_items(self.prompt):
            self.add_item(item)
        row = ui.ActionRow()
        confirm = ui.Button(
            label=self.confirm_label,
            style=discord.ButtonStyle.danger,
            custom_id=f"v2:{id(self)}:confirm",
        )
        confirm.callback = self._on_confirm
        cancel = ui.Button(
            label="Cancel",
            style=discord.ButtonStyle.secondary,
            custom_id=f"v2:{id(self)}:cancel",
        )
        cancel.callback = self._on_cancel
        row.add_item(confirm)
        row.add_item(cancel)
        self.add_item(row)

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.author_id:
            await interaction.response.send_message(
                "Only the invoker can confirm this.", ephemeral=True
            )
            return False
        return True

    async def _on_confirm(self, interaction: discord.Interaction) -> None:
        self.value = True
        self.stop()
        await interaction.response.edit_message(
            view=v2.text_layout("Confirmed.", accent=0x22C55E)
        )

    async def _on_cancel(self, interaction: discord.Interaction) -> None:
        self.value = False
        self.stop()
        await interaction.response.edit_message(
            view=v2.text_layout("Cancelled.", accent=0x64748B)
        )

    async def on_timeout(self) -> None:
        self.value = False
        if self.message is not None:
            try:
                await self.message.edit(view=v2.text_layout("Confirmation expired."))
            except discord.HTTPException:
                pass
