/* Home page: catalogue-backed category rail, featured commands, the hero
   ticker, spotlight cards, scroll reveals and the stat counters. */
(function () {
  "use strict";

  const data = window.COMMAND_DATA;
  const labelFor = (key) => {
    const found = data ? (data.categories || []).find((row) => row.key === key) : null;
    return found ? found.label : key;
  };

  /* ── category rail ─────────────────────────────────────────────────────── */

  const catColumn = document.getElementById("homeCategories");
  if (catColumn && data) {
    const cats = (data.categories || []).filter((row) => row.count > 0);
    cats.forEach((row) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "cat-row";
      button.innerHTML = `<span>${row.label}</span><b>${row.count}</b>`;
      button.addEventListener("click", () => {
        window.location.href = `commands.html?cat=${encodeURIComponent(row.key)}`;
      });
      catColumn.appendChild(button);
    });
  }

  /* ── featured commands ─────────────────────────────────────────────────── */

  const featured = document.getElementById("homeFeatured");
  if (featured && data) {
    const head = document.createElement("div");
    head.className = "featured-head";
    head.innerHTML = `<span>Featured</span><span>${data.total} commands</span>`;
    featured.appendChild(head);

    const picks = ["vpncheck", "vanitycheck", "vanitywatch", "usernamecheck", "dns", "whois", "phishlure"];
    const rows = picks.map((name) => data.commands.find((row) => row.name === name)).filter(Boolean);

    rows.forEach((row, index) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "featured-row";
      const aliases = row.aliases.slice(0, 2).map((alias) => `<em> /${alias}</em>`).join("");
      button.innerHTML = `
        <span class="n">${String(index + 1).padStart(2, "0")}</span>
        <span>
          <span class="name">.${row.name}${aliases}</span>
          <span class="brief">${row.brief}</span>
        </span>
        <span class="go">Open</span>`;
      button.addEventListener("click", () => {
        if (window.CommandDrawer) window.CommandDrawer.open(row.name);
        else window.location.href = `commands.html#cmd-${row.name.replace(/\s+/g, "-")}`;
      });
      featured.appendChild(button);
    });
  }

  /* ── hero lookup bar ───────────────────────────────────────────────────── */

  const select = document.getElementById("lookupCategory");
  if (select && data) {
    (data.categories || [])
      .filter((row) => row.count > 0)
      .forEach((row) => {
        const option = document.createElement("option");
        option.value = row.key;
        option.textContent = `${labelFor(row.key)} · ${row.count}`;
        select.appendChild(option);
      });
  }

  const form = document.getElementById("lookupForm");
  if (form) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const query = (document.getElementById("lookupQuery").value || "").trim();
      const hint = document.getElementById("lookupHint").value;
      const category = select ? select.value : "all";
      const params = new URLSearchParams();
      const term = query || hint;
      if (term) params.set("q", term);
      if (category && category !== "all") params.set("cat", category);
      window.location.href = `commands.html${params.toString() ? `?${params}` : ""}`;
    });
  }

  /* ── spotlight that follows the pointer on bento tiles ─────────────────── */

  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const fine = window.matchMedia("(pointer: fine)").matches;
  if (fine && !reduced) {
    document.querySelectorAll(".tile, .tool-card").forEach((node) => {
      node.addEventListener("pointermove", (event) => {
        const box = node.getBoundingClientRect();
        node.style.setProperty("--mx", `${event.clientX - box.left}px`);
        node.style.setProperty("--my", `${event.clientY - box.top}px`);
      });
    });
  }

  /* ── reveal sections as they enter the viewport ────────────────────────── */

  const targets = document.querySelectorAll(
    ".page-section > .wrap, .hero-grid, .cta-band > .wrap, .footer-grid"
  );
  if (!reduced && "IntersectionObserver" in window) {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("is-in");
          observer.unobserve(entry.target);
        });
      },
      { rootMargin: "0px 0px -12% 0px", threshold: 0.06 }
    );
    targets.forEach((node) => {
      node.classList.add("reveal");
      observer.observe(node);
    });
  }

  /* ── counters ──────────────────────────────────────────────────────────── */

  const counters = document.querySelectorAll("[data-count]");
  if (counters.length && !reduced && "IntersectionObserver" in window) {
    const animate = (node) => {
      const target = Number(node.dataset.count) || 0;
      const start = performance.now();
      const duration = 900;
      const step = (now) => {
        const progress = Math.min(1, (now - start) / duration);
        const eased = 1 - Math.pow(1 - progress, 3);
        node.textContent = Math.round(target * eased);
        if (progress < 1) window.requestAnimationFrame(step);
      };
      window.requestAnimationFrame(step);
    };
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          animate(entry.target);
          observer.unobserve(entry.target);
        });
      },
      { threshold: 0.4 }
    );
    counters.forEach((node) => observer.observe(node));
  }
})();
