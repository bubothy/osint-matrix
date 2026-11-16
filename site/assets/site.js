/* Shared shell behaviour: nav, scroll progress, copy buttons, active page. */
(function () {
  "use strict";

  const page = document.body.dataset.page || "";
  const toggle = document.querySelector(".nav-toggle");
  const links = document.querySelector(".nav-links");

  if (toggle && links) {
    toggle.addEventListener("click", () => {
      const open = links.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });
    links.addEventListener("click", (event) => {
      if (event.target.closest("a")) {
        links.classList.remove("open");
        toggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  document.querySelectorAll(".nav-links a[data-page]").forEach((link) => {
    if (link.dataset.page === page) link.setAttribute("aria-current", "page");
  });

  const bar = document.querySelector(".nav-progress span");
  if (bar) {
    const paint = () => {
      const doc = document.documentElement;
      const travel = doc.scrollHeight - doc.clientHeight;
      bar.style.width = travel > 0 ? `${Math.min(100, (doc.scrollTop / travel) * 100)}%` : "0%";
    };
    paint();
    window.addEventListener("scroll", paint, { passive: true });
    window.addEventListener("resize", paint);
  }

  /* copy buttons: <button class="icon-btn" data-copy="text"> */
  const flash = (el, text) => {
    const original = el.textContent;
    el.textContent = text;
    el.classList.add("copied");
    window.setTimeout(() => {
      el.textContent = original;
      el.classList.remove("copied");
    }, 1100);
  };

  const write = async (value) => {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch (error) {
      const area = document.createElement("textarea");
      area.value = value;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      let ok = false;
      try {
        ok = document.execCommand("copy");
      } catch (err) {
        ok = false;
      }
      document.body.removeChild(area);
      return ok;
    }
  };

  document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-copy]");
    if (!button) return;
    event.preventDefault();
    const source = button.dataset.copy;
    const value = source && source.startsWith("#") ? (document.querySelector(source) || {}).value || "" : source;
    if (!value) return;
    const ok = await write(value);
    flash(button, ok ? "copied" : "failed");
  });

  window.copyText = write;

  /* gentle parallax tilt for the floating console */
  const tilt = document.querySelector("[data-tilt]");
  if (tilt && !window.matchMedia("(prefers-reduced-motion: reduce)").matches && window.matchMedia("(pointer: fine)").matches) {
    tilt.addEventListener("pointermove", (event) => {
      const box = tilt.getBoundingClientRect();
      const x = (event.clientX - box.left) / box.width - 0.5;
      const y = (event.clientY - box.top) / box.height - 0.5;
      tilt.style.transform = `rotateX(${(-y * 4 + 2).toFixed(2)}deg) rotateY(${(x * 6 - 3).toFixed(2)}deg)`;
    });
    tilt.addEventListener("pointerleave", () => {
      tilt.style.transform = "";
    });
  }
})();

/* ═══ 3D interactions ══════════════════════════════════════════════════════ */

(function () {
  "use strict";

  const fine = window.matchMedia("(pointer: fine)").matches;
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* hero stage: pointer-driven parallax on the perspective scene */
  const stage = document.querySelector("[data-stage]");
  const stageInner = document.querySelector("[data-stage-inner]");
  if (stage && stageInner && fine && !reduced) {
    stage.addEventListener("pointermove", (event) => {
      const box = stage.getBoundingClientRect();
      const px = (event.clientX - box.left) / box.width - 0.5;
      const py = (event.clientY - box.top) / box.height - 0.5;
      stage.style.setProperty("--px", px.toFixed(3));
      stage.style.setProperty("--py", py.toFixed(3));
    });
    stage.addEventListener("pointerleave", () => {
      stage.style.setProperty("--px", "0");
      stage.style.setProperty("--py", "0");
    });
  }

  /* perspective carousel */
  document.querySelectorAll("[data-carousel]").forEach((root) => {
    const track = root.querySelector("[data-carousel-track]");
    if (!track) return;
    const slides = Array.from(track.querySelectorAll(".slide"));
    if (!slides.length) return;
    const dots = root.querySelector("[data-carousel-dots]");
    const prev = root.querySelector("[data-carousel-prev]");
    const next = root.querySelector("[data-carousel-next]");
    let index = Math.max(0, slides.findIndex((slide) => slide.dataset.start === "true")) || 0;

    const paint = () => {
      slides.forEach((slide, position) => {
        const offset = position - index;
        slide.dataset.offset = String(offset);
        const hidden = Math.abs(offset) > 2;
        slide.dataset.hidden = String(hidden);
        slide.setAttribute("aria-hidden", String(hidden || offset !== 0));
        const link = slide.querySelector(".slide-open");
        if (link) link.tabIndex = offset === 0 ? 0 : -1;
      });
      if (dots) {
        Array.from(dots.children).forEach((dot, position) => {
          dot.setAttribute("aria-current", String(position === index));
        });
      }
    };

    const go = (nextIndex) => {
      index = (nextIndex + slides.length) % slides.length;
      paint();
    };

    if (dots) {
      dots.innerHTML = "";
      slides.forEach((slide, position) => {
        const dot = document.createElement("button");
        dot.type = "button";
        dot.className = "carousel-dot";
        dot.setAttribute("aria-label", `Show ${slide.querySelector("h3")?.textContent || `slide ${position + 1}`}`);
        dot.addEventListener("click", () => go(position));
        dots.appendChild(dot);
      });
    }

    prev?.addEventListener("click", () => go(index - 1));
    next?.addEventListener("click", () => go(index + 1));

    root.addEventListener("keydown", (event) => {
      if (event.key === "ArrowLeft") {
        event.preventDefault();
        go(index - 1);
      } else if (event.key === "ArrowRight") {
        event.preventDefault();
        go(index + 1);
      }
    });

    slides.forEach((slide, position) => {
      slide.addEventListener("click", (event) => {
        if (event.target.closest("a")) return;
        if (position === index) {
          const link = slide.querySelector(".slide-open");
          if (link) window.location.href = link.href;
          return;
        }
        go(position);
      });
      slide.style.cursor = position === index ? "pointer" : "default";
    });

    let startX = null;
    root.addEventListener("pointerdown", (event) => {
      startX = event.clientX;
    });
    root.addEventListener("pointerup", (event) => {
      if (startX === null) return;
      const delta = event.clientX - startX;
      startX = null;
      if (Math.abs(delta) > 46) go(index + (delta < 0 ? 1 : -1));
    });

    paint();
  });

  /* command marquee in the footer */
  const footer = document.querySelector("footer");
  if (footer && !footer.querySelector(".marquee")) {
    const data = window.COMMAND_DATA;
    let names = data && Array.isArray(data.commands)
      ? data.commands.filter((row) => !row.name.startsWith("gen ")).slice(0, 28).map((row) => row.name)
      : [];
    if (!names.length) {
      names = ["vanitycheck", "usernamecheck", "vanitywatch", "dns", "certs", "whois", "phishlure", "asn", "jwt", "robots"];
    }
    const marquee = document.createElement("div");
    marquee.className = "marquee";
    marquee.setAttribute("aria-hidden", "true");
    const track = document.createElement("div");
    track.className = "marquee-track";
    [...names, ...names].forEach((name) => {
      const item = document.createElement("span");
      item.textContent = name;
      track.appendChild(item);
    });
    marquee.appendChild(track);
    const grid = footer.querySelector(".wrap") || footer;
    grid.insertBefore(marquee, grid.firstChild);
  }

  /* back to top */
  if (!document.querySelector(".to-top")) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "to-top";
    button.textContent = "↑";
    button.title = "Back to top";
    button.setAttribute("aria-label", "Back to top");
    button.dataset.visible = "false";
    button.addEventListener("click", () => window.scrollTo({ top: 0, behavior: reduced ? "auto" : "smooth" }));
    document.body.appendChild(button);
    const toggle = () => {
      button.dataset.visible = String(window.scrollY > 420);
    };
    toggle();
    window.addEventListener("scroll", toggle, { passive: true });
  }

  /* "/" focuses the command search */
  const search = document.getElementById("cmdSearch");
  if (search) {
    document.addEventListener("keydown", (event) => {
      const tag = (event.target.tagName || "").toLowerCase();
      if (event.key === "/" && !["input", "textarea", "select"].includes(tag)) {
        event.preventDefault();
        search.focus();
        search.select();
      }
    });
  }
})();
