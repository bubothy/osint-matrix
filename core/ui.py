"""Interactive components: pagination and confirmation."""

from __future__ import annotations

from typing import Sequence

import discord


class Paginator(discord.ui.View):
    """Five-button paginator bound to the invoking user."""

    def __init__(self, pages: Sequence[discord.Embed], *, author_id: int | None = None, timeout: float = 240) -> None:
        super().__init__(timeout=timeout)
        self.pages: list[discord.Embed] = list(pages) or [
            discord.Embed(title="No results", description="Nothing to display.")
        ]
        self.author_id = author_id
        self.index = 0
        self.message: discord.Message | None = None
        self._sync()

    # ── state ────────────────────────────────────────────────────────────

    @property
    def page(self) -> discord.Embed:
        embed = self.pages[self.index]
        total = len(self.pages)
        if total > 1:
            existing = (embed.footer.text or "").split("  •  page ")[0]
            marker = f"page {self.index + 1}/{total}"
            embed.set_footer(text=(existing + "  •  " + marker) if existing else marker)
        return embed

    def _sync(self) -> None:
        last = len(self.pages) - 1
        self.first.disabled = self.index == 0
        self.previous.disabled = self.index == 0
        self.next.disabled = self.index >= last
        self.last.disabled = self.index >= last
        self.counter.label = f"{self.index + 1}/{len(self.pages)}"

    async def _guard(self, interaction: discord.Interaction) -> bool:
        if self.author_id is not None and interaction.user.id != self.author_id:
            await interaction.response.send_message(
                "This result belongs to someone else. Run the command yourself.", ephemeral=True
            )
            return False
        return True

    async def _update(self, interaction: discord.Interaction) -> None:
        self._sync()
        await interaction.response.edit_message(embed=self.page, view=self)

    # ── buttons ──────────────────────────────────────────────────────────

    @discord.ui.button(emoji="⏮", style=discord.ButtonStyle.secondary)
    async def first(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        if await self._guard(interaction):
            self.index = 0
            await self._update(interaction)

    @discord.ui.button(emoji="◀", style=discord.ButtonStyle.primary)
    async def previous(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        if await self._guard(interaction):
            self.index = max(0, self.index - 1)
            await self._update(interaction)

    @discord.ui.button(label="1/1", style=discord.ButtonStyle.secondary, disabled=True)
    async def counter(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        await interaction.response.defer()

    @discord.ui.button(emoji="▶", style=discord.ButtonStyle.primary)
    async def next(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        if await self._guard(interaction):
            self.index = min(len(self.pages) - 1, self.index + 1)
            await self._update(interaction)

    @discord.ui.button(emoji="⏭", style=discord.ButtonStyle.secondary)
    async def last(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        if await self._guard(interaction):
            self.index = len(self.pages) - 1
            await self._update(interaction)

    @discord.ui.button(emoji="✖", style=discord.ButtonStyle.danger, row=1)
    async def close(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        if await self._guard(interaction):
            self.stop()
            await interaction.response.edit_message(view=None)

    async def on_timeout(self) -> None:
        for child in self.children:
            child.disabled = True  # type: ignore[attr-defined]
        if self.message is not None:
            try:
                await self.message.edit(view=self)
            except discord.HTTPException:
                pass


class Confirm(discord.ui.View):
    """Two-button destructive-action confirmation."""

    def __init__(self, *, author_id: int, confirm_label: str = "Confirm", timeout: float = 60) -> None:
        super().__init__(timeout=timeout)
        self.author_id = author_id
        self.value: bool | None = None
        self.confirm.label = confirm_label

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.author_id:
            await interaction.response.send_message("Only the invoker can confirm this.", ephemeral=True)
            return False
        return True

    @discord.ui.button(label="Confirm", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        self.value = True
        self.stop()
        await interaction.response.edit_message(
            embed=discord.Embed(description="Confirmed.", color=0x22C55E), view=None
        )

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        self.value = False
        self.stop()
        await interaction.response.edit_message(
            embed=discord.Embed(description="Cancelled.", color=0x64748B), view=None
        )
