/* Access console: edits the same document the bot enforces, offline. */
(function () {
  "use strict";

  const DEFAULTS = {
    brand: "0SWALD",
    prefix: ".",
    approval_required: true,
    allow_dms: true,
    maintenance: false,
    maintenance_note: "The operator has locked this instance to owners only. Try again once maintenance ends.",
    denied_note: "This instance is private. Your Discord ID is not on the operator's allow-list.",
    log_channel_id: "",
    rate_limit_per_10s: 8,
    cooldown_seconds: 10,
    watch_interval: 60,
    max_watches: 8,
    audit: true,
    notes: "",
    updated_at: "",
  };

  const RANGES = {
    rate_limit_per_10s: [1, 30],
    cooldown_seconds: [1, 120],
    watch_interval: [30, 3600],
    max_watches: [1, 25],
  };

  const LIMITS = { brand: 60, prefix: 5, maintenance_note: 320, denied_note: 320, log_channel_id: 24, notes: 600 };
  const BOOLS = ["approval_required", "allow_dms", "maintenance", "audit"];
  const STORE = "0swald.access.v1";
  const PAIR = "0swald.pair.v1";

  const form = document.getElementById("accessForm");
  if (!form) return;

  const fields = {};
  form.querySelectorAll("[data-field]").forEach((input) => {
    fields[input.dataset.field] = input;
  });

  const status = document.getElementById("accessStatus");
  const risks = document.getElementById("accessRisks");
  const preview = document.getElementById("accessPreview");
  const summary = document.getElementById("accessSummary");
  const exportBox = document.getElementById("accessExport");
  const commandBox = document.getElementById("accessCommand");
  const commandMeta = document.getElementById("accessCommandMeta");
  const importBox = document.getElementById("accessImport");
  const importNote = document.getElementById("accessImportNote");
  const keyInput = document.getElementById("accessKeyInput");
  const keyState = document.getElementById("accessKeyState");

  const say = (node, text, flash) => {
    if (!node) return;
    node.textContent = text;
    if (flash) {
      node.classList.add("flash");
      window.setTimeout(() => node.classList.remove("flash"), 1400);
    }
  };

  const clamp = (value, low, high) => Math.max(low, Math.min(high, value));

  const normalise = (raw) => {
    const cfg = { ...DEFAULTS };
    if (raw && typeof raw === "object") {
      Object.keys(DEFAULTS).forEach((key) => {
        if (key in raw) cfg[key] = raw[key];
      });
    }
    BOOLS.forEach((key) => {
      cfg[key] = Boolean(cfg[key]);
    });
    Object.entries(LIMITS).forEach(([key, limit]) => {
      const text = String(cfg[key] ?? "").trim().slice(0, limit);
      cfg[key] = text || (key === "brand" || key === "prefix" ? DEFAULTS[key] : "");
    });
    Object.entries(RANGES).forEach(([key, [low, high]]) => {
      const value = Number.parseInt(cfg[key], 10);
      cfg[key] = clamp(Number.isFinite(value) ? value : DEFAULTS[key], low, high);
    });
    cfg.log_channel_id = /^\d+$/.test(String(cfg.log_channel_id).trim()) ? String(cfg.log_channel_id).trim() : "";
    cfg.prefix = cfg.prefix.slice(0, 5) || ".";
    return cfg;
  };

  const readForm = () => {
    const cfg = {};
    Object.entries(fields).forEach(([key, input]) => {
      if (input.type === "checkbox") cfg[key] = input.checked;
      else if (input.type === "number") cfg[key] = Number.parseInt(input.value, 10);
      else cfg[key] = input.value;
    });
    return normalise(cfg);
  };

  const writeForm = (cfg) => {
    Object.entries(fields).forEach(([key, input]) => {
      if (input.type === "checkbox") input.checked = Boolean(cfg[key]);
      else input.value = cfg[key] ?? "";
    });
    form.querySelectorAll("[data-counter]").forEach((node) => {
      const input = fields[node.dataset.counter];
      if (!input) return;
      const limit = LIMITS[node.dataset.counter] || 0;
      const length = String(input.value).length;
      node.textContent = limit ? `${length}/${limit}` : String(length);
      node.classList.toggle("over", limit > 0 && length > limit);
    });
  };

  const base64url = (text) => {
    const bytes = new TextEncoder().encode(text);
    let binary = "";
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  const fromBase64url = (text) => {
    const clean = String(text).trim().replace(/`/g, "").replace(/\s+/g, "");
    if (!clean) throw new Error("That export is empty.");
    const padded = clean.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (clean.length % 4)) % 4);
    let binary;
    try {
      binary = atob(padded);
    } catch (error) {
      throw new Error("That does not look like an access export.");
    }
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    const text2 = new TextDecoder().decode(bytes);
    let data;
    try {
      data = JSON.parse(text2);
    } catch (error) {
      throw new Error("The export decoded to something that is not JSON.");
    }
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("The export is not a configuration object.");
    return data;
  };

  /* Python's json.dumps(..., sort_keys=True, separators=(",", ":")) */
  const encode = (cfg) => {
    const ordered = {};
    const clean = normalise(cfg);
    Object.keys(DEFAULTS)
      .sort()
      .forEach((key) => {
        ordered[key] = clean[key];
      });
    return base64url(JSON.stringify(ordered));
  };

  const debate = (cfg) => {
    const owner = "always allowed";
    let approved;
    if (cfg.maintenance) approved = "blocked · maintenance";
    else approved = cfg.approval_required ? "allowed · on the allow-list" : "allowed · approval is off";
    let stranger;
    if (cfg.maintenance) stranger = "blocked · maintenance";
    else stranger = cfg.approval_required ? "blocked · not approved" : "allowed · approval is off";
    const dm = cfg.allow_dms ? "allowed" : "blocked · DMs off";
    return [
      ["Owner", owner, "owner"],
      ["Approved member", approved, cfg.maintenance ? "no" : "yes"],
      ["Stranger", stranger, cfg.maintenance || cfg.approval_required ? "no" : "yes"],
      ["DM lookup", dm, cfg.allow_dms ? "yes" : "no"],
      ["Dispatch ceiling", `${cfg.rate_limit_per_10s} lookups / ${cfg.cooldown_seconds}s`, "—"],
      ["Sniper polling", `${cfg.watch_interval}s floor · ${cfg.max_watches} watches`, cfg.watch_interval >= 45 ? "yes" : "risky"],
    ];
  };

  const warnings = (cfg) => {
    const notes = [];
    if (!cfg.approval_required) notes.push("Approval is off, so anyone who can see the bot can run commands.");
    if (cfg.maintenance) notes.push("Maintenance lock is on, so approved users cannot run commands.");
    if (!cfg.allow_dms) notes.push("Direct messages are disabled; slash commands work in servers only.");
    if (cfg.rate_limit_per_10s > 15) notes.push("A ceiling above 15 per 10s is unusual for a private instance.");
    if (cfg.watch_interval < 45) notes.push("An interval below 45s will hit Discord's rate limits.");
    if (!cfg.audit) notes.push("Audit logging is off, so the audit feed stays empty.");
    return notes;
  };

  const persist = (cfg) => {
    try {
      localStorage.setItem(STORE, JSON.stringify(cfg));
    } catch (error) {
      /* storage can be disabled; the console still works in-session */
    }
  };

  const render = () => {
    const cfg = readForm();
    persist(cfg);

    if (risks) {
      risks.innerHTML = "";
      const notes = warnings(cfg);
      if (!notes.length) {
        const row = document.createElement("div");
        row.className = "risk none";
        row.innerHTML = "<span>✓</span><span>No warnings. This configuration is conservative.</span>";
        risks.appendChild(row);
      } else {
        notes.forEach((note) => {
          const row = document.createElement("div");
          row.className = "risk";
          row.innerHTML = `<span>!</span><span>${note}</span>`;
          risks.appendChild(row);
        });
      }
    }

    if (preview) {
      preview.innerHTML = "";
      debate(cfg).forEach(([who, outcome, allowed]) => {
        const row = document.createElement("tr");
        row.innerHTML = `<td>${who}</td><td>${outcome}</td><td>${allowed}</td>`;
        preview.appendChild(row);
      });
    }

    if (summary) {
      const rows = [
        ["brand", cfg.brand],
        ["prefix", cfg.prefix],
        ["approval", cfg.approval_required ? "required" : "open"],
        ["maintenance", cfg.maintenance ? "on" : "off"],
        ["dms", cfg.allow_dms ? "on" : "off"],
        ["log channel", cfg.log_channel_id || "disabled"],
        ["rate limit", `${cfg.rate_limit_per_10s} / ${cfg.cooldown_seconds}s`],
        ["watch interval", `${cfg.watch_interval}s`],
        ["max watches", String(cfg.max_watches)],
        ["audit", cfg.audit ? "on" : "off"],
      ];
      summary.innerHTML = rows
        .map(([key, value]) => `<div class="gate" style="grid-template-columns:1fr auto"><h4>${key}</h4><p class="mono" style="color:#fff">${String(value).slice(0, 42)}</p></div>`)
        .join("");
    }

    const blob = encode(cfg);
    if (exportBox) exportBox.value = blob;
    const command = `${cfg.prefix}accessimport ${blob}`;
    if (commandBox) commandBox.value = command;
    if (commandMeta) {
      const length = command.length;
      commandMeta.textContent = `${length} / 2000 characters${length > 1900 ? " · too long for one message" : " · fits in one message"}`;
      commandMeta.style.color = length > 1900 ? "#fff" : "";
    }
    say(status, `editing · ${Object.keys(DEFAULTS).length - 1} fields · saved in this browser`, false);
  };

  form.addEventListener("input", (event) => {
    const counter = form.querySelector(`[data-counter="${event.target.dataset.field}"]`);
    if (counter) {
      const limit = LIMITS[event.target.dataset.field] || 0;
      counter.textContent = limit ? `${event.target.value.length}/${limit}` : String(event.target.value.length);
      counter.classList.toggle("over", limit > 0 && event.target.value.length > limit);
    }
    render();
  });
  form.addEventListener("change", render);
  form.addEventListener("submit", (event) => event.preventDefault());

  document.querySelectorAll("[data-preset]").forEach((button) => {
    button.addEventListener("click", () => {
      const preset = button.dataset.preset;
      let cfg = readForm();
      let message = "preset applied";
      if (preset === "locked") {
        cfg = { ...cfg, approval_required: true, allow_dms: false, maintenance: false, audit: true, rate_limit_per_10s: 6, cooldown_seconds: 10, watch_interval: 60, max_watches: 5 };
        message = "preset applied · locked down";
      } else if (preset === "open") {
        cfg = { ...cfg, approval_required: false, allow_dms: true, maintenance: false, audit: true, rate_limit_per_10s: 10, cooldown_seconds: 10, watch_interval: 60, max_watches: 8 };
        message = "preset applied · open instance";
      } else if (preset === "hunt") {
        cfg = { ...cfg, approval_required: true, allow_dms: true, maintenance: false, audit: true, rate_limit_per_10s: 10, cooldown_seconds: 10, watch_interval: 45, max_watches: 12 };
        message = "preset applied · sniper heavy";
      } else if (preset === "frozen") {
        cfg = { ...cfg, maintenance: true };
        message = "preset applied · maintenance lock";
      } else {
        cfg = { ...DEFAULTS };
        message = "reset to defaults";
      }
      writeForm(normalise(cfg));
      render();
      say(status, message, true);
    });
  });

  const load = () => {
    let cfg = { ...DEFAULTS };
    try {
      const stored = localStorage.getItem(STORE);
      if (stored) cfg = normalise(JSON.parse(stored));
    } catch (error) {
      cfg = { ...DEFAULTS };
    }
    writeForm(cfg);
    render();
  };

  const importButton = document.getElementById("accessImportRun");
  if (importButton) {
    importButton.addEventListener("click", () => {
      const raw = importBox ? importBox.value : "";
      try {
        const cfg = normalise(fromBase64url(raw));
        writeForm(cfg);
        render();
        const count = Object.keys(cfg).filter((key) => key !== "updated_at" && cfg[key] !== DEFAULTS[key]).length;
        say(importNote, `loaded · ${count} field(s) differ from defaults`, true);
        say(status, "import applied to the form · review, then send it back with the generated command", true);
      } catch (error) {
        say(importNote, error.message, false);
        if (importNote) importNote.style.color = "#fff";
      }
    });
  }

  const downloadButton = document.getElementById("accessDownload");
  if (downloadButton) {
    downloadButton.addEventListener("click", () => {
      const cfg = readForm();
      const body = `${cfg.prefix}accessimport ${encode(cfg)}\n`;
      const link = document.createElement("a");
      link.href = URL.createObjectURL(new Blob([body], { type: "text/plain" }));
      link.download = "access.export.txt";
      link.click();
      URL.revokeObjectURL(link.href);
      say(status, "export written to access.export.txt", true);
    });
  }

  const copyCommand = document.getElementById("accessCopyCommand");
  if (copyCommand) {
    copyCommand.addEventListener("click", async () => {
      const ok = await window.copyText(commandBox.value);
      say(status, ok ? "command copied · paste it into Discord" : "copy failed; select the text manually", true);
    });
  }

  const copyBlob = document.getElementById("accessCopyBlob");
  if (copyBlob) {
    copyBlob.addEventListener("click", async () => {
      const ok = await window.copyText(exportBox.value);
      say(status, ok ? "export copied" : "copy failed", true);
    });
  }

  /* pairing key: stored in this browser only, never transmitted */
  const paintKey = () => {
    if (!keyInput || !keyState) return;
    let key = "";
    try {
      key = sessionStorage.getItem(PAIR) || "";
    } catch (error) {
      key = "";
    }
    if (!key) {
      keyState.textContent = "no key loaded · the console still works offline";
      keyInput.value = "";
      return;
    }
    keyState.textContent = `loaded · ${key.slice(0, 9)}…${key.slice(-4)} · kept in this tab only`;
    keyInput.value = key;
  };

  const keySave = document.getElementById("accessKeySave");
  if (keySave && keyInput) {
    keySave.addEventListener("click", () => {
      const value = keyInput.value.trim();
      if (!value) {
        try {
          sessionStorage.removeItem(PAIR);
        } catch (error) {
          /* ignore */
        }
        paintKey();
        say(keyState, "key cleared from this tab");
        return;
      }
      if (!/^osx_[a-f0-9]{32,}$/i.test(value)) {
        say(keyState, "that does not look like an osx_ key; mint one with .accesskey rotate");
        return;
      }
      try {
        sessionStorage.setItem(PAIR, value);
      } catch (error) {
        say(keyState, "this browser refused session storage");
        return;
      }
      paintKey();
    });
  }

  const keyClear = document.getElementById("accessKeyClear");
  if (keyClear && keyInput) {
    keyClear.addEventListener("click", () => {
      try {
        sessionStorage.removeItem(PAIR);
      } catch (error) {
        /* ignore */
      }
      keyInput.value = "";
      say(keyState, "no key loaded · the console still works offline");
    });
  }

  load();
  paintKey();
})();
