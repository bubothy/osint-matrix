/* The hero console: a small offline emulator of the real command set.
   Nothing here calls the network. Every answer is canned, so the site works
   from a plain static server. */
(function () {
  "use strict";

  const root = document.querySelector("[data-terminal]");
  if (!root) return;

  const out = root.querySelector(".term-body");
  const form = root.querySelector(".term-input-row");
  const input = root.querySelector("input");
  const limit = 260;
  const history = [];
  let cursor = -1;

  const line = (text, cls = "") => {
    const node = document.createElement("div");
    node.className = `term-line ${cls}`.trim();
    node.textContent = text;
    out.appendChild(node);
    while (out.children.length > limit) out.removeChild(out.firstChild);
    out.scrollTop = out.scrollHeight;
  };

  const rule = () => line("─".repeat(58), "rule");
  const pad = (text, width) => String(text).padEnd(width, " ");

  const banner = () => {
    line("0SWALD · offline demo console", "hl");
    line("The real bot sends these reports in Discord. This shell is a mock-up;", "dim");
    line("no requests leave your browser, and the deployed bot answers only", "dim");
    line("approved operator IDs.", "dim");
    rule();
    line("Type `help` for the demo commands, or tap one below.", "muted");
  };

  const commands = {
    help() {
      line("DEMO COMMANDS", "hl");
      rule();
      line("  vpncheck <ip>           VPN / proxy / Tor verdict");
      line("  vanitycheck <code>      invite code intelligence");
      line("  vanitysnipe <code>      availability + claim checklist");
      line("  vanitywatch <codes>     batch watch, up to eight codes");
      line("  usernamecheck <name>    handle availability on seven platforms");
      line("  usernamesnipe <name>    drop-window plan for a handle");
      line("  phishlure <domain>      lookalike-risk scoring");
      line("  dns <domain>            record set summary");
      line("  certs <domain>          certificate transparency summary");
      line("  commands                point at the full index");
      line("  clear                   wipe the pane");
      rule();
      line("Each of these is a real command in the index.", "dim");
    },

    vanitycheck(args) {
      const code = (args[0] || "matrix").replace(/^.*\//, "").split("?")[0];
      line(`.vanitycheck ${code}`, "hl");
      rule();
      line(`INVITE      discord.gg/${code}`);
      line("STATE       resolved · public server");
      line("SERVER      THE MATRIX");
      line("MEMBERS     41,208");
      line("ONLINE      6,942");
      line("CREATED     2019-04-11");
      line("OWNER       hidden (privacy settings)");
      line("FEATURES    ANIMATED_ICON · BANNER · COMMUNITY");
      line("VANITY      custom · edgeless");
      line("RISK        none observed in public metadata", "warn");
      rule();
      line("8 fields · split by section when the output grows.", "dim");
    },

    vanitysnipe(args) {
      const code = (args[0] || "void").replace(/^.*\//, "").split("?")[0];
      line(`.vanitysnipe ${code}`, "hl");
      rule();
      line(`TARGET      discord.gg/${code}`);
      line("STATUS      available", "warn");
      line("WINDOW      unknown; monitor rather than poll");
      line("REQUIREMENTS  tier 3 boosts or partner status on the claiming guild");
      line("PLAN        1. confirm claim rights on the guild");
      line("            2. run .vanitywatch to track release windows");
      line("            3. claim manually from Server Settings → Vanity URL");
      line("NOTE        availability is flaky by design; the watcher caches 30s", "dim");
    },

    vanitywatch(args) {
      const codes = args.length ? args : ["void", "hex", "null"];
      line(`.vanitywatch ${codes.join(" ")}`, "hl");
      rule();
      codes.slice(0, 8).forEach((code, index) => {
        line(`${pad(`[${String(index + 1).padStart(2, "0")}]`, 6)}${pad(code, 14)}tracking · interval ${30 + index * 0}s`);
      });
      rule();
      line(`watchtower armed · ${Math.min(codes.length, 8)} of 8 slots used`, "warn");
      line("Change events post once per transition, not once per poll.", "dim");
    },

    usernamecheck(args) {
      const name = args[0] || "greed";
      line(`.usernamecheck ${name}`, "hl");
      rule();
      line(`HANDLE      @${name}`);
      line("DISCORD     taken (user id hidden)");
      line("GITHUB      available");
      line("TELEGRAM    taken");
      line("REDDIT      available");
      line("X           taken");
      line("STEAM       available");
      line("SCORE       4 of 7 platforms free", "warn");
      line("PIVOT       `@greed.dev` · `greed_ops` · `greed.hq`", "dim");
    },

    usernamesnipe(args) {
      const name = args[0] || "greed";
      line(`.usernamesnipe ${name}`, "hl");
      rule();
      line(`TARGET      @${name}`);
      line("STATE       held; release is not schedulable");
      line("ATTEMPTS    manual only; automation violates ToS");
      line("PREP        1. reserve 3 fallbacks you would accept");
      line("            2. keep a second account warmed up");
      line("            3. watch the handle with .usernamecheck");
      line("ETHICS      no guessing, no credential use, no account access", "warn");
    },

    phishlure(args) {
      const domain = args[0] || "paypa1.com";
      line(`.phishlure ${domain}`, "hl");
      rule();
      line(`INPUT       ${domain}`);
      line("HOMOGRAPH   digit substitution (1 → l)");
      line("DISTANCE    edit distance 1 from the brand");
      line("TLD         .com · high-abuse registrar space");
      line("SCORE       87/100 · HIGH", "warn");
      line("VERDICT     treat as a lookalike; report and block");
      line("NOTE        scores defensively; nothing is registered", "dim");
    },

    dns(args) {
      const domain = args[0] || "example.com";
      line(`.dns ${domain}`, "hl");
      rule();
      line("A           93.184.216.34");
      line("AAAA        2606:2800:220:1:248:1893:25c8:1946");
      line("MX          0 .");
      line("NS          a.iana-servers.net · b.iana-servers.net");
      line("TXT         v=spf1 -all");
      line("CAA         0 issue \"digicert.com\"");
    },

    certs(args) {
      const domain = args[0] || "example.com";
      line(`.certs ${domain}`, "hl");
      rule();
      line("LOGGED      412 certificates");
      line("LATEST      2026-09-02 · 90 days · Let's Encrypt");
      line("SUBDOMAINS  www · api · mail · staging");
      line("NOTE        first-seen dates expose rollout history", "dim");
    },

    vpncheck(args) {
      const ip = args[0] || "1.1.1.1";
      const tor = ip.startsWith("171.25.");
      line(`.vpncheck ${ip}`, "hl");
      rule();
      line(`CLASSIFICATION  ${tor ? "Tor exit node" : "Datacenter or cloud"}`);
      line(`CONFIDENCE      ${tor ? "88" : "88"}%`);
      line(`SIGNALS         ${tor ? "tor · proxy · hosting" : "hosting · no VPN · no Tor"}`);
      line(`PROVIDER        ${tor ? "DFRI" : "Cloudflare, Inc."}`);
      line(`NETWORK         ${tor ? "AS198093" : "AS13335"} · ${tor ? "Sweden" : "Australia"}`);
      line(`EXPOSURE        ${tor ? "100" : "55"}/100`, "warn");
      rule();
      line("Merged from ipquery.io and ip-api.com; provider names need a key.", "dim");
      line("A clean verdict means nothing was flagged, not that it is a real person.", "dim");
    },

    whoami() {
      line("You are a guest of the demo shell.", "hl");
      line("The deployed bot is private: your Discord ID must be on the", "dim");
      line("operator's allow-list before any command runs.", "dim");
    },

    commands() {
      line("The full list is on the Commands page: 380 commands", "hl");
      line("and 626 callable names including aliases.", "muted");
      line("→ commands.html", "dim");
    },

    clear() {
      out.innerHTML = "";
      banner();
    },
  };

  const aliases = {
    vc: "vanitycheck",
    vanity: "vanitycheck",
    vcheck: "vanitycheck",
    vs: "vanitysnipe",
    vsnipe: "vanitysnipe",
    vw: "vanitywatch",
    vbatch: "vanitywatch",
    ucheck: "usernamecheck",
    un: "usernamecheck",
    usnipe: "usernamesnipe",
    phish: "phishlure",
    vpn: "vpncheck",
    ipvpn: "vpncheck",
    anonymity: "vpncheck",
    dns: "dns",
    "?": "help",
    ls: "help",
  };

  const run = (raw) => {
    const text = raw.trim();
    if (!text) return;
    line(`› ${text}`, "dim");
    const parts = text.replace(/^[.!]/, "").split(/\s+/);
    const key = parts.shift().toLowerCase();
    const name = commands[key] ? key : aliases[key];
    if (!name || !commands[name]) {
      line(`unknown command: ${key}; try \`help\``, "warn");
      return;
    }
    commands[name](parts);
  };

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const value = input.value;
    input.value = "";
    if (value.trim()) {
      history.push(value.trim());
      cursor = history.length;
    }
    run(value);
  });

  input.addEventListener("keydown", (event) => {
    if (event.key === "ArrowUp") {
      event.preventDefault();
      if (!history.length) return;
      cursor = Math.max(0, cursor - 1);
      input.value = history[cursor] || "";
      input.setSelectionRange(input.value.length, input.value.length);
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      if (!history.length) return;
      cursor = Math.min(history.length, cursor + 1);
      input.value = history[cursor] || "";
    } else if (event.key === "Tab") {
      event.preventDefault();
      const partial = input.value.replace(/^[.!]/, "").trim();
      if (!partial) return;
      const match = Object.keys(commands).find((name) => name.startsWith(partial));
      if (match) input.value = match;
    }
  });

  root.querySelectorAll("[data-run]").forEach((chip) => {
    chip.addEventListener("click", () => {
      const command = chip.dataset.run;
      input.value = command;
      history.push(command);
      cursor = history.length;
      run(command);
      input.focus();
    });
  });

  banner();
  line("", "dim");
  run("vpncheck 1.1.1.1");
  out.scrollTop = 0;
})();
