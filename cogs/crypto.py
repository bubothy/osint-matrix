"""Crypto intelligence: public ledger address and transaction lookups."""

from __future__ import annotations

import hashlib
import re
from decimal import Decimal
from typing import Any

from discord.ext import commands

from core.command import intel
from core.embeds import Intel
from core.errors import IntelError, NotFound, SourceUnavailable, UsageError
from core.utils import ack, clip, fmt_dt, num, require, utcnow

BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

ADDRESS_KINDS: list[tuple[str, str, str]] = [
    ("Bitcoin — Bech32m (Taproot)", r"^bc1p[02-9ac-hj-np-z]{11,71}$", "P2TR, BIP-341"),
    ("Bitcoin — Bech32 (segwit)", r"^bc1[02-9ac-hj-np-z]{11,71}$", "P2WPKH / P2WSH, BIP-173"),
    ("Bitcoin — P2PKH", r"^1[1-9A-HJ-NP-Za-km-z]{25,34}$", "legacy base58check"),
    ("Bitcoin — P2SH", r"^3[1-9A-HJ-NP-Za-km-z]{25,34}$", "script hash"),
    ("Ethereum / EVM", r"^0x[a-fA-F0-9]{40}$", "20-byte account, EIP-55 display"),
    ("Litecoin", r"^(?:L|M)[1-9A-HJ-NP-Za-km-z]{26,33}$", "base58check"),
    ("Dogecoin", r"^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$", "base58check"),
    ("Monero", r"^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$", "CryptoNote, 95 chars"),
    ("Tron", r"^T[1-9A-HJ-NP-Za-km-z]{33}$", "base58check"),
    ("Ripple", r"^r[1-9A-HJ-NP-Za-km-z]{24,34}$", "XRP ledger classic address"),
    ("Solana", r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", "base58 ed25519 public key"),
    ("Cardano", r"^addr1[02-9ac-hj-np-z]{20,100}$", "Bech32 Shelley address"),
    ("Bitcoin Cash", r"^(?:bitcoincash:)?[qp][02-9ac-hj-np-z]{41}$", "cashaddr"),
    ("NEAR", r"^[a-z0-9_-]{2,64}\.near$", "named account"),
    ("ENS", r"^[a-z0-9-]+\.eth$", "Ethereum name service"),
]


def b58decode(value: str) -> bytes:
    number = 0
    for char in value:
        if char not in BASE58:
            raise ValueError("not base58")
        number = number * 58 + BASE58.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    padding = len(value) - len(value.lstrip("1"))
    return b"\x00" * padding + raw


def b58check(value: str) -> bool:
    try:
        raw = b58decode(value)
    except ValueError:
        return False
    if len(raw) < 5:
        return False
    payload, checksum = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum


def btc_amount(satoshis: Any) -> str:
    try:
        return f"{Decimal(int(satoshis)) / Decimal(100_000_000):.8f} BTC"
    except (TypeError, ValueError):
        return "—"


class Crypto(commands.Cog, name="Crypto"):
    """Public blockchain intelligence. No wallets, keys or transactions are created."""

    def __init__(self, bot: Any) -> None:
        self.bot = bot
        self.http = bot.http

    # ── helpers ──────────────────────────────────────────────────────────

    async def _blockstream(self, path: str) -> Any:
        return await self.http.get_json(
            f"https://blockstream.info/api{path}", cache_ttl=120, timeout=20
        )

    async def _eth(self, method: str, params: list[Any]) -> Any:
        response = await self.http.request(
            "POST",
            "https://cloudflare-eth.com",
            json_body={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            cache=False,
            timeout=20,
        )
        if not response.ok:
            raise SourceUnavailable(f"The Ethereum RPC endpoint answered HTTP {response.status}.")
        payload = response.json()
        if payload.get("error"):
            raise IntelError(f"Ethereum RPC error: {payload['error'].get('message', 'unknown')}")
        return payload.get("result")

    async def _sol(self, method: str, params: list[Any]) -> Any:
        response = await self.http.request(
            "POST",
            "https://api.mainnet-beta.solana.com",
            json_body={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            cache=False,
            timeout=20,
        )
        if not response.ok:
            raise SourceUnavailable(f"The Solana RPC endpoint answered HTTP {response.status}.")
        payload = response.json()
        if payload.get("error"):
            raise IntelError(f"Solana RPC error: {payload['error'].get('message', 'unknown')}")
        return payload.get("result")

    # ── Bitcoin ──────────────────────────────────────────────────────────

    @intel(
        category="crypto",
        brief="Bitcoin address dossier: balance, lifetime flows, transaction count and recent activity.",
        usage="<address>",
        aliases=["btcaddr"],
        examples=["btc bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"],
        sources=["blockstream.info"],
        cooldown=(2, 15),
    )
    async def btc(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        address = require(target, "Bitcoin address", example=".btc bc1q...").strip()
        if not re.fullmatch(r"(bc1[02-9ac-hj-np-z]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34})", address.lower()):
            raise UsageError("That is not a valid Bitcoin address.")
        payload = await self._blockstream(f"/address/{address}")
        chain = payload.get("chain_stats") or {}
        mempool = payload.get("mempool_stats") or {}
        received = int(chain.get("funded_txo_sum") or 0)
        sent = int(chain.get("spent_txo_sum") or 0)
        balance = received - sent
        recent: list[dict[str, Any]] = []
        try:
            recent = await self._blockstream(f"/address/{address}/txs") or []
        except IntelError:
            recent = []
        embed = Intel(
            category="crypto",
            command="btc",
            ctx=ctx,
            target=address,
            summary="Public ledger data only. Addresses are pseudonymous: clustering is inference, not identity.",
        )
        embed.kv(
            "BALANCE",
            {
                "Confirmed": btc_amount(balance),
                "Unconfirmed delta": btc_amount(
                    int(mempool.get("funded_txo_sum") or 0) - int(mempool.get("spent_txo_sum") or 0)
                ),
                "Satoshis": num(balance),
                "Received (lifetime)": btc_amount(received),
                "Sent (lifetime)": btc_amount(sent),
            },
            inline=True,
        )
        embed.kv(
            "ACTIVITY",
            {
                "Transactions": num(chain.get("tx_count")),
                "UTXOs": num(int(chain.get("funded_txo_count") or 0) - int(chain.get("spent_txo_count") or 0)),
                "Inputs funded": num(chain.get("funded_txo_count")),
                "Outputs spent": num(chain.get("spent_txo_count")),
                "Mempool transactions": num(mempool.get("tx_count")),
            },
            inline=True,
        )
        if recent:
            embed.code(
                "RECENT TRANSACTIONS",
                "\n".join(f"{tx.get('txid', '?')[:64]}  {str((tx.get('status') or {}).get('block_height') or 'mempool')}" for tx in recent[:8]),
                lang="yaml",
            )
            embed.kv(
                "LATEST",
                {
                    "TXID": recent[0].get("txid"),
                    "Confirmed": (recent[0].get("status") or {}).get("confirmed"),
                    "Block": (recent[0].get("status") or {}).get("block_height"),
                    "Value out": btc_amount(sum(int(out.get("value") or 0) for out in recent[0].get("vout") or [])),
                },
                inline=False,
            )
        if address.lower().startswith(("bc1p", "bc1q")):
            embed.kv("FORMAT", {"Type": "SegWit v1 (Taproot)" if address.lower().startswith("bc1p") else "SegWit v0", "Checksum": "bech32"}, inline=True)
        else:
            embed.kv("FORMAT", {"Type": "Legacy/P2SH", "Base58check valid": b58check(address)}, inline=True)
        embed.risk(0, name="SCREENING", verdict="PUBLIC LEDGER ONLY")
        embed.source("blockstream.info")
        await embed.send(ctx)

    @intel(
        category="crypto",
        brief="Bitcoin transaction detail: confirmations, fee, inputs and outputs.",
        usage="<txid>",
        aliases=["tx"],
        examples=["btctx 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"],
        sources=["blockstream.info"],
        cooldown=(2, 15),
    )
    async def btctx(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        txid = require(target, "Bitcoin transaction ID", example=".btctx <64 hex characters>").strip()
        if not re.fullmatch(r"[a-fA-F0-9]{64}", txid):
            raise UsageError("A Bitcoin txid is 64 hexadecimal characters.")
        payload = await self._blockstream(f"/tx/{txid}")
        status = payload.get("status") or {}
        outputs = payload.get("vout") or []
        total_out = sum(int(out.get("value") or 0) for out in outputs)
        embed = Intel(
            category="crypto",
            command="btctx",
            ctx=ctx,
            target=txid[:24] + "…",
            summary="Transaction-level view: what moved, what it cost and whether it is final.",
        )
        embed.kv(
            "TRANSACTION",
            {
                "TXID": payload.get("txid"),
                "Version": payload.get("version"),
                "Size": f"{num(payload.get('size'))} bytes",
                "Weight": num(payload.get("weight")),
                "Fee": btc_amount(payload.get("fee")),
                "Value out": btc_amount(total_out),
                "Locktime": payload.get("locktime"),
            },
            inline=True,
        )
        embed.kv(
            "STATUS",
            {
                "Confirmed": status.get("confirmed"),
                "Block height": status.get("block_height"),
                "Block hash": status.get("block_hash"),
                "Block time": fmt_dt(status.get("block_time")),
                "Confirmations": num((utcnow().timestamp() - status["block_time"]) // 600) if status.get("block_time") else "0 (mempool)",
            },
            inline=True,
        )
        embed.kv(
            "STRUCTURE",
            {
                "Inputs": len(payload.get("vin") or []),
                "Outputs": len(outputs),
                "SegWit": any("witness" in (entry or {}) for entry in payload.get("vin") or []),
                "Fee rate": f"{(payload.get('fee') or 0) / max(1, payload.get('weight') or 1) * 4:.1f} sat/vB",
            },
            inline=True,
        )
        if outputs:
            embed.code(
                "OUTPUTS",
                "\n".join(
                    f"{index:>2}  {btc_amount(out.get('value')):>18}  {clip(str((out.get('scriptpubkey_address') or 'non-standard')), 60)}"
                    for index, out in enumerate(outputs[:8])
                ),
                lang="yaml",
            )
        embed.source("blockstream.info")
        await embed.send(ctx)

    @intel(
        category="crypto",
        brief="Bitcoin block header and statistics by height or hash.",
        usage="<height|hash>",
        aliases=["btcblock"],
        examples=["block 800000"],
        sources=["blockstream.info"],
        cooldown=(2, 15),
    )
    async def block(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "block height or hash", example=".block 800000").strip()
        if raw.isdigit():
            block_hash = await self.http.get_text(
                f"https://blockstream.info/api/block-height/{raw}", cache_ttl=600, timeout=20
            )
            block_hash = block_hash.strip()
        elif re.fullmatch(r"[a-fA-F0-9]{64}", raw):
            block_hash = raw
        else:
            raise UsageError("Supply a block height (digits) or a 64-character block hash.")
        payload = await self._blockstream(f"/block/{block_hash}")
        embed = Intel(
            category="crypto",
            command="block",
            ctx=ctx,
            target=str(payload.get("height", raw)),
            summary="Block headers anchor every transaction below them. Timestamp, difficulty and merkle root are the useful pivots.",
        )
        embed.kv(
            "HEADER",
            {
                "Hash": payload.get("id"),
                "Height": payload.get("height"),
                "Version": payload.get("version"),
                "Timestamp": fmt_dt(payload.get("timestamp")),
                "Merkle root": payload.get("merkle_root"),
                "Previous": payload.get("previousblockhash"),
                "Nonce": payload.get("nonce"),
                "Bits": payload.get("bits"),
            },
            inline=False,
        )
        embed.kv(
            "STATISTICS",
            {
                "Transactions": num(payload.get("tx_count")),
                "Size": f"{num(payload.get('size'))} bytes",
                "Weight": num(payload.get("weight")),
                "Difficulty": payload.get("difficulty"),
                "Age": fmt_dt(payload.get("timestamp")),
            },
            inline=True,
        )
        embed.source("blockstream.info")
        await embed.send(ctx)

    # ── Ethereum ─────────────────────────────────────────────────────────

    @intel(
        category="crypto",
        brief="Ethereum account state: balance, nonce, contract status and activity.",
        usage="<address>",
        aliases=["ethaddr"],
        examples=["eth 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"],
        sources=["cloudflare-eth.com"],
        cooldown=(2, 15),
    )
    async def eth(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        address = require(target, "Ethereum address", example=".eth 0xd8dA...").strip()
        if not re.fullmatch(r"0x[a-fA-F0-9]{40}", address):
            raise UsageError("Ethereum addresses are `0x` followed by 40 hexadecimal characters.")
        balance_hex = await self._eth("eth_getBalance", [address, "latest"])
        nonce_hex = await self._eth("eth_getTransactionCount", [address, "latest"])
        code = await self._eth("eth_getCode", [address, "latest"])
        balance = int(balance_hex or "0x0", 16) if isinstance(balance_hex, str) else 0
        nonce = int(nonce_hex or "0x0", 16) if isinstance(nonce_hex, str) else 0
        is_contract = isinstance(code, str) and code not in {"0x", "0x0", ""}
        eth_value = Decimal(balance) / Decimal(10**18)
        embed = Intel(
            category="crypto",
            command="eth",
            ctx=ctx,
            target=address,
            summary="Account state read directly from a public JSON-RPC endpoint. No transaction is signed or broadcast.",
        )
        embed.kv(
            "ACCOUNT",
            {
                "Balance": f"{eth_value:.6f} ETH",
                "Wei": num(balance),
                "Nonce": num(nonce),
                "Type": "contract" if is_contract else "externally owned account",
                "Code size": f"{len(code) // 2 - 1} bytes" if is_contract else "none",
                "Network": "Ethereum mainnet",
            },
            inline=True,
        )
        embed.kv(
            "INTERPRETATION",
            {
                "Outgoing transactions": num(nonce),
                "Dormant": nonce == 0 and balance == 0,
                "Address case": "checksummed display" if any(char.isupper() for char in address[2:]) else "lowercase",
                "Explorer": f"https://etherscan.io/address/{address}",
            },
            inline=True,
        )
        embed.checks(
            "SIGNALS",
            [
                (is_contract, "Contract account", "bytecode deployed" if is_contract else "no bytecode"),
                (balance > 0, "Holds value", f"{eth_value:.6f} ETH"),
                (nonce > 0, "Has sent transactions", num(nonce)),
                (None, "Caution", "a balance is public; ownership is not"),
            ],
        )
        embed.source("cloudflare-eth.com")
        await embed.send(ctx)

    @intel(
        category="crypto",
        brief="Ethereum transaction and receipt: sender, recipient, value, gas and status.",
        usage="<tx hash>",
        examples=["ethtx 0x...64 hex"],
        sources=["cloudflare-eth.com"],
        cooldown=(2, 15),
    )
    async def ethtx(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        tx_hash = require(target, "Ethereum transaction hash", example=".ethtx 0x<64 hex>").strip()
        if not re.fullmatch(r"0x[a-fA-F0-9]{64}", tx_hash):
            raise UsageError("A transaction hash is `0x` plus 64 hexadecimal characters.")
        tx = await self._eth("eth_getTransactionByHash", [tx_hash])
        if not tx:
            raise NotFound("That transaction is unknown to the node (or still pending).")
        receipt = await self._eth("eth_getTransactionReceipt", [tx_hash]) or {}
        value = int(tx.get("value") or "0x0", 16) if isinstance(tx.get("value"), str) else 0
        gas_price = int(tx.get("gasPrice") or "0x0", 16) if isinstance(tx.get("gasPrice"), str) else 0
        gas_used = int(receipt.get("gasUsed") or "0x0", 16) if isinstance(receipt.get("gasUsed"), str) else 0
        fee = gas_used * gas_price
        embed = Intel(
            category="crypto",
            command="ethtx",
            ctx=ctx,
            target=tx_hash[:24] + "…",
            summary="Transaction plus its receipt, so success or revert is explicit rather than inferred.",
        )
        embed.kv(
            "TRANSFER",
            {
                "From": tx.get("from"),
                "To": tx.get("to") or "contract creation",
                "Value": f"{Decimal(value) / Decimal(10**18):.8f} ETH",
                "Nonce": int(tx.get("nonce") or "0x0", 16) if isinstance(tx.get("nonce"), str) else None,
                "Block": int(tx.get("blockNumber") or "0x0", 16) if tx.get("blockNumber") else "pending",
                "Type": tx.get("type"),
            },
            inline=True,
        )
        embed.kv(
            "GAS",
            {
                "Gas price": f"{Decimal(gas_price) / Decimal(10**9):.4f} gwei",
                "Gas used": num(gas_used),
                "Gas limit": int(tx.get("gas") or "0x0", 16) if isinstance(tx.get("gas"), str) else None,
                "Fee": f"{Decimal(fee) / Decimal(10**18):.8f} ETH",
            },
            inline=True,
        )
        embed.kv(
            "RECEIPT",
            {
                "Status": "success" if receipt.get("status") == "0x1" else "reverted" if receipt.get("status") else "unknown",
                "Logs": len(receipt.get("logs") or []),
                "Contract created": receipt.get("contractAddress"),
                "Cumulative gas": int(receipt.get("cumulativeGasUsed") or "0x0", 16) if receipt.get("cumulativeGasUsed") else None,
            },
            inline=True,
        )
        embed.checks(
            "VERDICT",
            [
                (receipt.get("status") == "0x1", "Execution succeeded", "receipt status 0x1" if receipt.get("status") == "0x1" else "reverted or pending"),
                (bool(tx.get("to")), "Recipient set", tx.get("to") or "contract creation"),
                (None, "Explorer", f"https://etherscan.io/tx/{tx_hash}"),
            ],
        )
        embed.source("cloudflare-eth.com")
        await embed.send(ctx)

    # ── Solana ───────────────────────────────────────────────────────────

    @intel(
        category="crypto",
        brief="Solana account balance and recent signature history.",
        usage="<address>",
        aliases=["solana"],
        examples=["sol <address>"],
        sources=["api.mainnet-beta.solana.com"],
        cooldown=(2, 15),
    )
    async def sol(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        address = require(target, "Solana address", example=".sol <base58 address>").strip()
        if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", address):
            raise UsageError("Solana addresses are 32–44 base58 characters.")
        balance = await self._sol("getBalance", [address])
        signatures: list[dict[str, Any]] = []
        try:
            signatures = await self._sol("getSignaturesForAddress", [address, {"limit": 10}]) or []
        except IntelError:
            signatures = []
        lamports = int((balance or {}).get("value") or 0)
        embed = Intel(
            category="crypto",
            command="sol",
            ctx=ctx,
            target=address,
            summary="Solana account state from a public RPC node. Signature history is capped at the most recent ten entries.",
        )
        embed.kv(
            "ACCOUNT",
            {
                "Lamports": num(lamports),
                "SOL": f"{Decimal(lamports) / Decimal(10**9):.9f}",
                "Rent exempt minimum": "0.00089088 SOL (typical)",
                "Executable": (balance or {}).get("executable"),
                "Recent signatures": len(signatures),
            },
            inline=True,
        )
        if signatures:
            embed.code(
                "RECENT ACTIVITY",
                "\n".join(
                    f"{str(entry.get('blockTime') or '')[:10]:10}  {str(entry.get('confirmationStatus') or '?'):12}  {entry.get('signature', '?')[:44]}"
                    for entry in signatures[:8]
                ),
                lang="yaml",
            )
            latest = signatures[0]
            embed.kv(
                "LATEST",
                {
                    "Signature": latest.get("signature"),
                    "Slot": latest.get("slot"),
                    "Block time": fmt_dt(latest.get("blockTime")),
                    "Error": latest.get("err") or "none",
                },
                inline=False,
            )
        embed.source("Solana RPC")
        await embed.send(ctx)

    # ── address classification ───────────────────────────────────────────

    @intel(
        category="crypto",
        brief="Classify an address across 15 chain formats and validate what can be validated locally.",
        usage="<address>",
        aliases=["coin", "detect"],
        examples=["address bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"],
        sources=["local computation"],
        cooldown=(4, 8),
    )
    async def address(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "crypto address", example=".address bc1q...").strip()
        matches = []
        for label, pattern, note in ADDRESS_KINDS:
            if re.fullmatch(pattern, raw if label.startswith(("Ethereum", "ENS", "NEAR")) else raw.lower()):
                matches.append((label, note))
        checks: list[tuple[bool | None, str, str]] = []
        if not matches:
            checks.append((False, "Unrecognised format", "no known chain pattern matched"))
        else:
            checks.extend((True, label, note) for label, note in matches)
        if raw.lower().startswith(("1", "3", "bc1")) or raw.lower().startswith(("l", "m", "d")):
            checks.append((b58check(raw), "Base58check", "valid checksum" if b58check(raw) else "checksum failed or bech32"))
        embed = Intel(
            category="crypto",
            command="address",
            ctx=ctx,
            target=clip(raw, 100),
            summary="Format classification is local and heuristic. Several chains share the base58 alphabet, so ambiguity is expected.",
        )
        embed.kv(
            "CANDIDATES",
            {
                "Matches": [label for label, _ in matches] or ["none"],
                "Length": len(raw),
                "Prefix": raw[:4],
                "Case": "mixed (checksum possible)" if raw != raw.lower() and raw != raw.upper() else "single case",
                "Characters": "base58" if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", raw) else "hex/base58mix" if re.fullmatch(r"[a-fA-F0-9x]+", raw) else "bech32/other",
            },
            inline=True,
        )
        embed.checks("FORMAT CHECKS", checks)
        embed.risk(0, name="SCREENING", verdict="FORMAT ONLY")
        embed.quote("This command never queries a chain. Use `btc`, `eth`, `sol` or `block` for ledger data on a confirmed format.")
        embed.source("local computation")
        await embed.send(ctx)


async def setup(bot: Any) -> None:
    await bot.add_cog(Crypto(bot))
