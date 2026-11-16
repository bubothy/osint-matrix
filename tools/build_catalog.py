"""Generate site/assets/commands.js from the cogs.

The website must never invent a command, so its catalogue is extracted from the
source instead of being maintained by hand. Run this after adding a command:

    python tools/build_catalog.py

Decorated commands are read from the AST, and the registry-based cogs
(``_TOOLS`` in toolkit, ``_ARSENAL`` in arsenal) are read from their list
literals. Nothing is imported, so this works without a Discord token.
"""

from __future__ import annotations

import ast
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATEGORY_LABELS = {
    "network": "Network",
    "domain": "Domain",
    "web": "Web",
    "identity": "Identity",
    "social": "Social",
    "discord": "Discord",
    "vuln": "Vulnerability",
    "crypto": "Crypto",
    "craft": "Craft",
    "toolkit": "Toolkit",
    "generator": "Generator",
    "system": "System",
}

items: list[dict] = []
seen: set[str] = set()


def literal(node: ast.AST, default=None):
    try:
        return ast.literal_eval(node)
    except Exception:
        return default


def docstring(node: ast.AST) -> str:
    text = ast.get_docstring(node) or ""
    return text.strip().splitlines()[0] if text.strip() else ""


def add(name, category, brief, usage, aliases=(), sources=()):
    if not name or name.startswith("_") or name in seen:
        return
    seen.add(name)
    items.append(
        {
            "name": name,
            "category": category,
            "brief": (brief or "").strip() or "No description recorded.",
            "usage": (usage or name).strip(),
            "aliases": list(aliases or ()),
            "sources": list(sources or ()),
        }
    )


for path in sorted((ROOT / "cogs").glob("*.py")):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            func = decorator.func
            kw = {item.arg: literal(item.value) for item in decorator.keywords if item.arg}
            if getattr(func, "id", "") == "intel":
                add(
                    kw.get("name") or node.name,
                    kw.get("category") or "system",
                    kw.get("brief") or docstring(node),
                    kw.get("usage") or node.name,
                    kw.get("aliases") or (),
                    kw.get("sources") or (),
                )
            elif isinstance(func, ast.Attribute) and func.attr == "command":
                parent = getattr(func.value, "id", "")
                if parent == "gen":
                    sub = kw.get("name") or node.name
                    suffix = ("[" + kw["usage"] + "]") if kw.get("usage") else ""
                    add(
                        f"gen {sub}",
                        "generator",
                        docstring(node),
                        f"gen {sub} {suffix}".strip(),
                    )
                elif parent == "commands":
                    add(
                        kw.get("name") or node.name,
                        "system",
                        docstring(node),
                        kw.get("usage") or node.name,
                        kw.get("aliases") or (),
                    )

for filename, listname, shape in (
    ("cogs/toolkit.py", "_TOOLS", "toolkit"),
    ("cogs/arsenal.py", "_ARSENAL", "arsenal"),
):
    tree = ast.parse((ROOT / filename).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if not any(getattr(target, "id", "") == listname for target in targets):
            continue
        if not isinstance(node.value, ast.List):
            continue
        for element in node.value.elts:
            if not isinstance(element, ast.Tuple):
                continue
            values = [literal(part) for part in element.elts]
            if shape == "toolkit":
                name, brief, usage = values[0], values[1], values[2]
                aliases = values[4] if len(values) > 4 else ()
                add(name, "toolkit", brief, usage, aliases)
            else:
                name, category, brief, usage = values[0], values[1], values[2], values[3]
                aliases = values[5] if len(values) > 5 else ()
                sources = values[6] if len(values) > 6 else ()
                add(name, category, brief, usage, aliases, sources)

items.sort(
    key=lambda row: (
        list(CATEGORY_LABELS).index(row["category"]) if row["category"] in CATEGORY_LABELS else 99,
        row["name"],
    )
)

payload = {
    "categories": [
        {
            "key": key,
            "label": label,
            "count": sum(1 for row in items if row["category"] == key),
        }
        for key, label in CATEGORY_LABELS.items()
    ],
    "commands": items,
    "total": len(items),
    "routes": len(items) + sum(len(row["aliases"]) for row in items),
    "aliases": sum(len(row["aliases"]) for row in items),
}

target = ROOT / "site" / "assets" / "commands.js"
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(
    "// Generated from the cogs so the site cannot drift from the bot.\n"
    "// Rebuild with: python tools/build_catalog.py\n"
    "window.COMMAND_DATA = "
    + json.dumps(payload, indent=1, ensure_ascii=False)
    + ";\n",
    encoding="utf-8",
)
print(f"{payload['total']} commands · {payload['routes']} callable names · {payload['aliases']} aliases")
for row in payload["categories"]:
    if row["count"]:
        print(f"  {row['label']:<14} {row['count']:>3}")
