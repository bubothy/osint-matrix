/* Command index: filtering, search, pagination, deep links, command drawer. */
(function () {
  "use strict";

  const data = window.COMMAND_DATA;
  const grid = document.getElementById("cmdGrid");
  if (!data || !grid) return;

  const rail = document.getElementById("cmdRail");
  const search = document.getElementById("cmdSearch");
  const count = document.getElementById("cmdCount");
  const pager = document.getElementById("cmdPager");
  const perPage = document.getElementById("cmdPerPage");
  const stats = document.querySelectorAll("[data-stat]");

  const params = new URLSearchParams(window.location.search);
  const state = {
    category: params.get("cat") || "all",
    query: params.get("q") || "",
    page: Number(params.get("page")) || 1,
    size: Number(perPage && perPage.value) || 24,
  };

  if (search) search.value = state.query;

  stats.forEach((node) => {
    const key = node.dataset.stat;
    const value = key === "commands" ? data.total : key === "routes" ? data.routes : key === "aliases" ? data.aliases : 0;
    node.dataset.count = String(value);
    node.textContent = String(value);
  });

  const labels = new Map(data.categories.map((row) => [row.key, row.label]));
  const cats = data.categories.filter((row) => row.count > 0);

  const buildRail = () => {
    if (!rail) return;
    const rows = [{ key: "all", label: "All", count: data.total }, ...cats];
    rail.innerHTML = "";
    const title = document.createElement("div");
    title.className = "rail-title";
    title.textContent = "CATEGORIES";
    rail.appendChild(title);
    rows.forEach((row) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "rail-item";
      button.dataset.cat = row.key;
      button.setAttribute("aria-pressed", String(state.category === row.key));
      button.innerHTML = `${row.label}<span>${row.count}</span>`;
      button.addEventListener("click", () => {
        state.category = row.key;
        state.page = 1;
        rail.querySelectorAll(".rail-item").forEach((item) => {
          item.setAttribute("aria-pressed", String(item.dataset.cat === state.category));
        });
        render();
      });
      rail.appendChild(button);
    });
  };

  const matches = () => {
    const needle = state.query.trim().toLowerCase();
    return data.commands.filter((row) => {
      if (state.category !== "all" && row.category !== state.category) return false;
      if (!needle) return true;
      return (
        row.name.toLowerCase().includes(needle) ||
        row.brief.toLowerCase().includes(needle) ||
        row.usage.toLowerCase().includes(needle) ||
        row.aliases.some((alias) => alias.toLowerCase().includes(needle))
      );
    });
  };

  const openRow = (row) => {
    if (window.CommandDrawer && window.CommandDrawer.open(row.name)) return;
    const command = `.${row.name}`;
    if (window.copyText) window.copyText(command);
  };

  const row = (entry, position) => {
    const article = document.createElement("article");
    article.className = "cmd";
    article.id = `cmd-${entry.name.replace(/\s+/g, "-")}`;
    article.dataset.name = entry.name;
    article.tabIndex = 0;
    article.setAttribute("role", "button");
    article.setAttribute("aria-label", `Open ${entry.name}`);

    const inner = document.createElement("div");
    inner.className = "cmd-inner";

    const number = document.createElement("span");
    number.className = "cmd-n";
    number.textContent = String(position).padStart(3, "0");

    const main = document.createElement("div");

    const top = document.createElement("div");
    top.className = "cmd-top";
    const name = document.createElement("span");
    name.className = "cmd-name";
    name.innerHTML = `<span class="prefix">.</span>${entry.name}`;
    const cat = document.createElement("span");
    cat.className = "cmd-cat";
    cat.textContent = labels.get(entry.category) || entry.category;
    top.append(name, cat);

    const brief = document.createElement("p");
    brief.textContent = entry.brief;

    const usage = document.createElement("div");
    usage.className = "cmd-usage";
    usage.textContent = entry.usage ? `.${entry.usage}` : `.${entry.name}`;
    if (entry.aliases.length) {
      const em = document.createElement("em");
      em.textContent = `   /${entry.aliases.join("  /")}`;
      usage.appendChild(em);
    }

    main.append(top, brief, usage);

    const meta = document.createElement("div");
    meta.className = "cmd-meta";
    const aliasCount = document.createElement("span");
    aliasCount.className = "cmd-alias-count";
    aliasCount.textContent = entry.aliases.length
      ? `${entry.aliases.length} alias${entry.aliases.length === 1 ? "" : "es"}`
      : "no aliases";
    const open = document.createElement("span");
    open.className = "cmd-open";
    open.textContent = "Open →";
    meta.append(aliasCount, open);

    inner.append(number, main, meta);
    article.appendChild(inner);

    article.addEventListener("click", (event) => {
      event.preventDefault();
      openRow(entry);
    });
    article.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openRow(entry);
      }
    });
    return article;
  };

  const pageList = (current, total) => {
    const pages = [];
    if (total <= 7) {
      for (let i = 1; i <= total; i += 1) pages.push(i);
      return pages;
    }
    pages.push(1);
    const start = Math.max(2, current - 1);
    const end = Math.min(total - 1, current + 1);
    if (start > 2) pages.push("…");
    for (let i = start; i <= end; i += 1) pages.push(i);
    if (end < total - 1) pages.push("…");
    pages.push(total);
    return pages;
  };

  const renderPager = (totalPages) => {
    if (!pager) return;
    pager.innerHTML = "";
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = totalPages ? `Page ${state.page} of ${totalPages}` : "No results";

    const buttons = document.createElement("div");
    buttons.className = "pager-buttons";

    const step = (label, target, disabled, current) => {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = label;
      button.disabled = Boolean(disabled);
      if (current) button.setAttribute("aria-current", "true");
      if (!disabled && !current) {
        button.addEventListener("click", () => {
          state.page = target;
          render();
          window.scrollTo({ top: grid.getBoundingClientRect().top + window.scrollY - 110, behavior: "smooth" });
        });
      }
      buttons.appendChild(button);
    };

    step("«", 1, state.page === 1);
    step("‹", state.page - 1, state.page === 1);
    pageList(state.page, totalPages || 1).forEach((value) => {
      if (value === "…") {
        const gap = document.createElement("button");
        gap.type = "button";
        gap.textContent = "…";
        gap.disabled = true;
        buttons.appendChild(gap);
        return;
      }
      step(String(value), value, false, value === state.page);
    });
    step("›", state.page + 1, state.page >= totalPages);
    step("»", totalPages, state.page >= totalPages);

    pager.append(meta, buttons);
  };

  const render = () => {
    const rows = matches();
    const totalPages = Math.max(1, Math.ceil(rows.length / state.size));
    state.page = Math.min(Math.max(1, state.page), totalPages);
    const start = (state.page - 1) * state.size;
    const slice = rows.slice(start, start + state.size);

    grid.innerHTML = "";
    if (!slice.length) {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.innerHTML = `<strong>Nothing matches</strong>Try a shorter query, or clear the category filter.`;
      grid.appendChild(empty);
    } else {
      slice.forEach((entry, index) => grid.appendChild(row(entry, start + index + 1)));
    }

    if (count) {
      const label = state.category === "all" ? "all categories" : labels.get(state.category);
      count.textContent = `${rows.length} match${rows.length === 1 ? "" : "es"} · ${label}`;
    }
    renderPager(rows.length ? totalPages : 0);

    const url = new URL(window.location.href);
    if (state.query) url.searchParams.set("q", state.query);
    else url.searchParams.delete("q");
    if (state.category !== "all") url.searchParams.set("cat", state.category);
    else url.searchParams.delete("cat");
    if (state.page > 1) url.searchParams.set("page", String(state.page));
    else url.searchParams.delete("page");
    window.history.replaceState(null, "", url.pathname + (url.search || ""));
  };

  let debounce = 0;
  if (search) {
    search.addEventListener("input", () => {
      window.clearTimeout(debounce);
      debounce = window.setTimeout(() => {
        state.query = search.value;
        state.page = 1;
        render();
      }, 120);
    });
  }

  if (perPage) {
    perPage.value = String(state.size);
    perPage.addEventListener("change", () => {
      state.size = Number(perPage.value) || 24;
      state.page = 1;
      render();
    });
  }

  buildRail();
  render();
})();
