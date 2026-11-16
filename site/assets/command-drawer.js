/* Command drawer: opens one command and shows every name it answers to,
   its usage, and the commands that sit beside it. Used by the index and by
   the home page's featured rows. */
(function () {
  "use strict";

  const data = window.COMMAND_DATA;
  if (!data || !Array.isArray(data.commands)) return;

  const byName = new Map();
  data.commands.forEach((row) => byName.set(row.name.toLowerCase(), row));

  const labelFor = (key) => {
    const found = (data.categories || []).find((row) => row.key === key);
    return found ? found.label : key;
  };

  const invoke = (row) => (row.name.startsWith("gen ") ? `.${row.name}` : `.${row.name}`);
  const slug = (name) => name.replace(/\s+/g, "-").toLowerCase();

  const family = (name) => (name.startsWith("gen ") ? "gen" : name.split(/[\s-]/)[0]);

  const related = (row) => {
    const base = family(row.name);
    const pool = data.commands.filter((item) => item.name !== row.name);
    const scored = pool
      .map((item) => {
        let score = 0;
        if (family(item.name) === base) score += 6;
        if (item.category === row.category) score += 3;
        if (row.aliases.some((alias) => item.aliases.includes(alias))) score += 1;
        return { item, score };
      })
      .filter((entry) => entry.score > 0)
      .sort((a, b) => b.score - a.score || a.item.name.localeCompare(b.item.name))
      .slice(0, 8)
      .map((entry) => entry.item);
    return scored;
  };

  const copy = async (value, button) => {
    const ok = await (window.copyText ? window.copyText(value) : Promise.resolve(false));
    if (!button) return ok;
    const before = button.textContent;
    button.textContent = ok ? "copied" : "failed";
    window.setTimeout(() => {
      button.textContent = before;
    }, 1100);
    return ok;
  };

  const root = document.createElement("div");
  root.innerHTML = `
    <div class="drawer-scrim" data-drawer-scrim data-open="false"></div>
    <aside class="drawer" data-drawer data-open="false" role="dialog" aria-modal="true" aria-label="Command detail" tabindex="-1">
      <div class="drawer-top">
        <span data-drawer-kicker>Command</span>
        <button class="drawer-close" type="button" data-drawer-close aria-label="Close command detail">✕</button>
      </div>
      <div class="drawer-body" data-drawer-body></div>
    </aside>`;
  document.body.append(root);

  const scrim = root.querySelector("[data-drawer-scrim]");
  const panel = root.querySelector("[data-drawer]");
  const body = root.querySelector("[data-drawer-body]");
  const kicker = root.querySelector("[data-drawer-kicker]");

  let current = null;
  let lastFocus = null;

  const render = (row) => {
    current = row;
    kicker.textContent = `${labelFor(row.category)} · command`;
    const aliases = row.aliases || [];
    const neighbours = related(row);
    const names = [row.name, ...aliases];

    body.innerHTML = "";

    const title = document.createElement("h2");
    title.textContent = invoke(row);

    const brief = document.createElement("p");
    brief.className = "drawer-brief";
    brief.textContent = row.brief || "No description in the catalogue.";

    const usageBlock = document.createElement("div");
    usageBlock.className = "drawer-block";
    usageBlock.innerHTML = `<h4>Usage</h4>`;
    const usage = document.createElement("div");
    usage.className = "drawer-usage";
    const usageText = document.createElement("span");
    usageText.textContent = row.usage ? `.${row.usage}` : invoke(row);
    const usageCopy = document.createElement("button");
    usageCopy.type = "button";
    usageCopy.className = "copy-btn";
    usageCopy.textContent = "copy";
    usageCopy.addEventListener("click", () => copy(usageText.textContent, usageCopy));
    usage.append(usageText, usageCopy);
    usageBlock.append(usage);

    const namesBlock = document.createElement("div");
    namesBlock.className = "drawer-block";
    const namesHeading = document.createElement("h4");
    namesHeading.textContent = names.length > 1 ? `All names · ${names.length}` : "All names";
    const nameList = document.createElement("div");
    nameList.className = "name-list";
    names.forEach((name) => {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "name-chip";
      chip.innerHTML = `<span>${name}</span>${name === row.name ? "<small>primary</small>" : "<small>alias</small>"}`;
      chip.title = `Copy ${name}`;
      chip.addEventListener("click", () => copy(name, chip));
      nameList.appendChild(chip);
    });
    namesBlock.append(namesHeading, nameList);

    const relatedBlock = document.createElement("div");
    relatedBlock.className = "drawer-block";
    const relatedHeading = document.createElement("h4");
    relatedHeading.textContent = neighbours.length ? "Related commands" : "Related commands";
    relatedBlock.append(relatedHeading);
    if (neighbours.length) {
      const list = document.createElement("div");
      list.className = "related";
      neighbours.forEach((item) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "related-row";
        button.innerHTML = `<span class="rn">${invoke(item)}</span><span class="rc">${labelFor(item.category)}</span>`;
        button.addEventListener("click", () => {
          render(item);
          setHash(item.name);
          body.scrollTop = 0;
        });
        list.appendChild(button);
      });
      relatedBlock.append(list);
    } else {
      const empty = document.createElement("p");
      empty.className = "drawer-empty";
      empty.textContent = "Nothing else in this family yet.";
      relatedBlock.append(empty);
    }

    const sources = document.createElement("div");
    sources.className = "drawer-block";
    sources.innerHTML = `<h4>Sources</h4><p class="drawer-src">${
      row.sources && row.sources.length ? row.sources.join(" · ") : "Computed locally; no third-party source."
    }</p>`;

    const foot = document.createElement("p");
    foot.className = "drawer-foot";
    foot.textContent = "Public data only. Invite and handle checks never automate a claim or a follow-up.";

    body.append(title, brief, usageBlock, namesBlock, relatedBlock, sources, foot);
    panel.setAttribute("aria-label", `${row.name} command detail`);
  };

  let restoreTimer = 0;

  const setHash = (name, replace) => {
    const next = `#cmd-${slug(name)}`;
    if (window.location.hash === next) return;
    if (replace) {
      window.history.replaceState(null, "", next);
    } else {
      window.history.pushState(null, "", next);
    }
  };

  const open = (name, options) => {
    const row = byName.get(String(name).toLowerCase());
    if (!row) return false;
    if (!panel.dataset.open || panel.dataset.open === "false") lastFocus = document.activeElement;
    render(row);
    body.scrollTop = 0;
    scrim.dataset.open = "true";
    panel.dataset.open = "true";
    document.body.style.overflow = "hidden";
    window.clearTimeout(restoreTimer);
    window.setTimeout(() => panel.focus({ preventScroll: true }), 60);
    setHash(row.name, options && options.replace);
    return true;
  };

  const close = () => {
    if (panel.dataset.open !== "true") return;
    scrim.dataset.open = "false";
    panel.dataset.open = "false";
    document.body.style.overflow = "";
    current = null;
    if (window.location.hash.startsWith("#cmd-")) {
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
    }
    if (lastFocus && typeof lastFocus.focus === "function") {
      restoreTimer = window.setTimeout(() => lastFocus.focus({ preventScroll: true }), 30);
    }
  };

  scrim.addEventListener("click", close);
  root.querySelector("[data-drawer-close]").addEventListener("click", close);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") close();
  });

  window.addEventListener("popstate", () => {
    const match = window.location.hash.match(/^#cmd-(.+)$/);
    if (match) open(match[1], { replace: true });
    else close();
  });

  window.CommandDrawer = { open, close, current: () => current };

  /* rows injected by the page scripts call open() themselves */
  const initial = window.location.hash.match(/^#cmd-(.+)$/);
  if (initial) {
    window.setTimeout(() => open(initial[1], { replace: true }), 0);
  }
})();
