/* Embed studio: up to three embeds + message content, live Discord preview,
   drag reorder, validation, templates, undo/redo, JSON and webhook output.

   Everything runs in the browser. The builder models the webhook payload a
   bot would send, so what you copy is what Discord receives. */
(function () {
  "use strict";

  const MAX_EMBEDS = 3;
  const MAX_FIELDS = 25;
  const AUTOSAVE = "0swald.studio.v1";
  const HEX = /^#[0-9a-f]{6}$/i;
  const PALETTE = ["#ffffff", "#d4d4d4", "#8e8e8e", "#4f545c", "#1f1f1f", "#57f287", "#fee75c", "#ed4245", "#5865f2"];

  const root = document.getElementById("studio");
  if (!root) return;

  const $ = (selector, scope = document) => scope.querySelector(selector);
  const $$ = (selector, scope = document) => Array.from(scope.querySelectorAll(selector));

  const blankEmbed = () => ({
    author: { name: "", icon: "", url: "" },
    title: "",
    url: "",
    description: "",
    color: "#ffffff",
    fields: [],
    thumbnail: "",
    image: "",
    footer: { text: "", icon: "" },
    timestamp: false,
  });

  const blankState = () => ({
    content: "",
    username: "",
    avatar: "",
    embeds: [blankEmbed()],
    active: 0,
  });

  let state = blankState();
  let history = [];
  let future = [];
  let lastSnapshot = "";
  let structuralTimer = 0;

  const els = {
    content: $("#msgContent"),
    contentCount: $("#msgContentCount"),
    username: $("#msgUsername"),
    avatar: $("#msgAvatar"),
    tabs: $("#embedTabs"),
    preview: $("#preview"),
    fields: $("#fieldList"),
    jsonPane: $("#jsonPane"),
    curlPane: $("#curlPane"),
    validatePane: $("#validatePane"),
    status: $("#studioStatus"),
    importBox: $("#importBox"),
    importNote: $("#importNote"),
    colorInput: $("#colorHex"),
    swatches: $("#swatches"),
    activeLabel: $("#activeEmbedLabel"),
  };

  const current = () => state.embeds[state.active] || state.embeds[0];

  const note = (node, text) => {
    if (!node) return;
    node.textContent = text;
    node.style.color = String(text).startsWith("that is not") ? "#fff" : "";
  };

  const say = (text, flash = true) => {
    if (!els.status) return;
    els.status.textContent = text;
    if (flash) {
      els.status.classList.add("flash");
      window.setTimeout(() => els.status.classList.remove("flash"), 1500);
    }
  };

  const clamp = (text, max) => String(text || "").slice(0, max);

  /* ── serialisation ───────────────────────────────────────────────────── */

  const hexToInt = (hex) => {
    const clean = String(hex || "").replace("#", "");
    if (!/^[0-9a-f]{6}$/i.test(clean)) return 0xffffff;
    return Number.parseInt(clean, 16);
  };

  const rawEmbed = (embed) => {
    const out = {};
    if (embed.author.name) {
      out.author = { name: clamp(embed.author.name, 256) };
      if (embed.author.url) out.author.url = embed.author.url;
      if (embed.author.icon) out.author.icon_url = embed.author.icon;
    }
    if (embed.title) out.title = clamp(embed.title, 256);
    if (embed.url) out.url = embed.url;
    if (embed.description) out.description = clamp(embed.description, 4096);
    out.color = hexToInt(embed.color);
    if (embed.fields.length) {
      out.fields = embed.fields.map((field) => {
        const row = { name: clamp(field.name || "\u200b", 256), value: clamp(field.value || "\u200b", 1024) };
        if (field.inline) row.inline = true;
        return row;
      });
    }
    if (embed.thumbnail) out.thumbnail = { url: embed.thumbnail };
    if (embed.image) out.image = { url: embed.image };
    if (embed.footer.text) {
      out.footer = { text: clamp(embed.footer.text, 2048) };
      if (embed.footer.icon) out.footer.icon_url = embed.footer.icon;
    }
    if (embed.timestamp) out.timestamp = new Date().toISOString();
    return out;
  };

  const payload = () => {
    const out = {};
    if (state.content.trim()) out.content = clamp(state.content, 2000);
    if (state.username.trim()) out.username = clamp(state.username, 80);
    if (state.avatar.trim()) out.avatar_url = state.avatar.trim();
    const list = state.embeds
      .map(rawEmbed)
      .filter((embed) => Boolean(embed.title || embed.description || embed.author || embed.footer || embed.image || embed.thumbnail || (embed.fields && embed.fields.length)));
    if (list.length) out.embeds = list;
    return out;
  };

  const embedCharacters = (embed) =>
    String(embed.title || "").length +
    String(embed.description || "").length +
    String((embed.author && embed.author.name) || "").length +
    String((embed.footer && embed.footer.text) || "").length +
    (embed.fields || []).reduce(
      (sum, field) => sum + String(field.name || "").length + String(field.value || "").length,
      0
    );

  /* ── validation ──────────────────────────────────────────────────────── */

  const validate = () => {
    const issues = [];
    const total = (payload().embeds || []).length;
    const untouched =
      !state.content.trim() &&
      total === 0 &&
      state.embeds.every(
        (embed) => !embed.title && !embed.description && !embed.author.name && !embed.footer.text && !embed.fields.length
      );
    if (untouched) {
      return [{ level: "warn", text: "Empty draft: add a title, description or message content.", target: "e-title" }];
    }
    if (!state.content.trim() && total === 0) {
      issues.push({ level: "error", text: "Nothing to send: add message content or at least one embed field.", target: "msgContent" });
    }
    if (state.content.length > 2000) {
      issues.push({ level: "error", text: `Message content is ${state.content.length}/2000 characters.`, target: "msgContent" });
    }
    if (total > MAX_EMBEDS) {
      issues.push({ level: "error", text: `Discord accepts ${MAX_EMBEDS} embeds per message; this draft has ${total}.`, target: "embedTabs" });
    }

    state.embeds.forEach((embed, index) => {
      const where = `Embed ${index + 1}`;
      const active = index === state.active;
      const focus = (id) => (active ? id : "embedTabs");
      const push = (level, text, id) => issues.push({ level, text: `${where}: ${text}`, target: focus(id) });

      if (!embed.title && !embed.description && !embed.fields.length && !embed.author.name && !embed.footer.text && !embed.image && !embed.thumbnail) {
        push("warn", "empty embed; Discord will reject it", "e-title");
      }
      if (embed.title.length > 256) push("error", `title is ${embed.title.length}/256`, "e-title");
      if (embed.description.length > 4096) push("error", `description is ${embed.description.length}/4096`, "e-description");
      if (embed.author.name.length > 256) push("error", `author name is ${embed.author.name.length}/256`, "e-author-name");
      if (embed.footer.text.length > 2048) push("error", `footer is ${embed.footer.text.length}/2048`, "e-footer-text");
      if (!HEX.test(embed.color)) push("error", "colour must be a six-digit hex value", "e-color");
      if (embed.url && !/^https?:\/\//i.test(embed.url)) push("error", "title link must start with http(s)://", "e-url");
      if (embed.author.url && !/^https?:\/\//i.test(embed.author.url)) push("warn", "author link is not http(s); Discord will ignore it", "e-author-url");
      if (embed.image && !/^https?:\/\//i.test(embed.image)) push("warn", "image URL is not http(s); it will not render", "e-image");
      if (embed.thumbnail && !/^https?:\/\//i.test(embed.thumbnail)) push("warn", "thumbnail URL is not http(s); it will not render", "e-thumbnail");
      if (embed.fields.length > MAX_FIELDS) push("error", `${embed.fields.length}/${MAX_FIELDS} fields`, "addField");
      embed.fields.forEach((field, order) => {
        if (!field.name.trim()) push("warn", `field ${order + 1} has no name`, `field-${order}-name`);
        if (!field.value.trim()) push("warn", `field ${order + 1} has no value`, `field-${order}-value`);
        if (field.name.length > 256) push("error", `field ${order + 1} name is ${field.name.length}/256`, `field-${order}-name`);
        if (field.value.length > 1024) push("error", `field ${order + 1} value is ${field.value.length}/1024`, `field-${order}-value`);
      });
      if (embedCharacters(embed) > 6000) push("error", `embed is ${embedCharacters(embed)}/6000 characters`, "embedTabs");
    });

    const weight = (payload().embeds || []).reduce((sum, embed) => sum + embedCharacters(embed), 0) + state.content.length;
    if (weight > 6000) {
      issues.push({ level: "error", text: `Message total is ${weight}/6000 characters across all embeds.`, target: "msgContent" });
    }
    return issues;
  };

  /* ── preview rendering ───────────────────────────────────────────────── */

  const escapeHtml = (text) =>
    String(text || "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));

  const md = (text) => {
    let html = escapeHtml(text);
    html = html.replace(/```([\s\S]*?)```/g, (match, body) => `<pre style="background:#141414;border:1px solid #262626;padding:8px;margin:6px 0;overflow:auto;font-size:12px">${body.replace(/\n$/, "")}</pre>`);
    html = html.replace(/`([^`\n]+)`/g, "<code>$1</code>");
    html = html.replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>");
    html = html.replace(/__([^_\n]+)__/g, "<u>$1</u>");
    html = html.replace(/~~([^~\n]+)~~/g, "<s>$1</s>");
    html = html.replace(/(^|[\s(])\*([^*\n]+)\*/g, "$1<em>$2</em>");
    html = html.replace(/(^|[\s(])_([^_\n]+)_/g, "$1<em>$2</em>");
    html = html.replace(/\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
    html = html.replace(/^&gt; ?(.*)$/gm, '<span style="border-left:3px solid #4f545c;padding-left:10px;display:block;color:#b5b5b5">$1</span>');
    return html;
  };

  const initials = (name) => (name || "MATRIX").trim().slice(0, 2).toUpperCase();

  const paintPreview = () => {
    if (!els.preview) return;
    const authorName = state.username.trim() || "0SWALD";
    const avatar = state.avatar.trim();
    const stamp = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

    const wrap = document.createElement("div");
    wrap.className = "msg";

    const avatarNode = document.createElement("div");
    avatarNode.className = "msg-avatar";
    if (avatar) {
      const img = document.createElement("img");
      img.src = avatar;
      img.alt = "";
      img.onerror = () => {
        img.remove();
        avatarNode.textContent = initials(authorName);
      };
      avatarNode.appendChild(img);
    } else {
      avatarNode.textContent = initials(authorName);
    }

    const body = document.createElement("div");
    body.className = "msg-body";
    const header = document.createElement("div");
    header.className = "msg-header";
    header.innerHTML = `<span class="msg-author">${escapeHtml(authorName)}</span><span class="bot-tag">APP</span><span class="msg-stamp">Today at ${stamp}</span>`;
    body.appendChild(header);

    if (state.content.trim()) {
      const content = document.createElement("div");
      content.className = "msg-content";
      content.innerHTML = md(state.content);
      body.appendChild(content);
    }

    let drawn = 0;
    state.embeds.forEach((embed) => {
      const empty =
        !embed.title &&
        !embed.description &&
        !embed.author.name &&
        !embed.footer.text &&
        !embed.image &&
        !embed.thumbnail &&
        !embed.fields.length;
      if (empty) return;
      drawn += 1;
      const card = document.createElement("div");
      card.className = "embed-card";
      card.style.borderLeftColor = HEX.test(embed.color) ? embed.color : "#ffffff";

      if (embed.thumbnail) {
        const thumb = document.createElement("div");
        thumb.className = "embed-thumb";
        if (/^https?:\/\//i.test(embed.thumbnail)) {
          const img = document.createElement("img");
          img.src = embed.thumbnail;
          img.alt = "";
          thumb.appendChild(img);
        } else {
          thumb.textContent = "thumbnail";
        }
        card.appendChild(thumb);
      }

      if (embed.author.name) {
        const author = document.createElement("div");
        author.className = "embed-author";
        author.innerHTML = `<span class="ico">${embed.author.icon ? `<img src="${escapeHtml(embed.author.icon)}" alt="">` : ""}</span><span>${escapeHtml(embed.author.name)}</span>`;
        card.appendChild(author);
      }

      if (embed.title) {
        const title = document.createElement("div");
        title.className = "embed-title";
        title.innerHTML = embed.url
          ? `<a href="${escapeHtml(embed.url)}" target="_blank" rel="noopener">${escapeHtml(embed.title)}</a>`
          : escapeHtml(embed.title);
        card.appendChild(title);
      }

      if (embed.description) {
        const description = document.createElement("div");
        description.className = "embed-desc";
        description.innerHTML = md(embed.description);
        card.appendChild(description);
      }

      if (embed.fields.length) {
        const fields = document.createElement("div");
        fields.className = "embed-fields";
        embed.fields.forEach((field) => {
          const item = document.createElement("div");
          item.className = `embed-field-item${field.inline ? "" : " wide"}`;
          item.innerHTML = `<div class="n">${md(field.name || "\u200b")}</div><div class="v">${md(field.value || "\u200b")}</div>`;
          fields.appendChild(item);
        });
        card.appendChild(fields);
      }

      if (embed.image) {
        const image = document.createElement("div");
        image.className = "embed-image";
        if (/^https?:\/\//i.test(embed.image)) {
          const img = document.createElement("img");
          img.src = embed.image;
          img.alt = "";
          image.appendChild(img);
        } else {
          image.textContent = "image URL";
        }
        card.appendChild(image);
      }

      if (embed.footer.text) {
        const footer = document.createElement("div");
        footer.className = "embed-footer";
        const icon = embed.footer.icon ? `<span class="favatar"><img src="${escapeHtml(embed.footer.icon)}" alt=""></span>` : "";
        footer.innerHTML = `${icon}<span>${escapeHtml(embed.footer.text)}</span><span class="sep">•</span><span>Today at ${stamp}</span>`;
        card.appendChild(footer);
      } else if (embed.timestamp) {
        const footer = document.createElement("div");
        footer.className = "embed-footer";
        footer.textContent = `Today at ${stamp}`;
        card.appendChild(footer);
      }

      body.appendChild(card);
    });

    if (!drawn) {
      const placeholder = document.createElement("div");
      placeholder.className = "stage-neutral";
      placeholder.textContent = "Empty embed · add a title, description or field";
      body.appendChild(placeholder);
    }

    wrap.append(avatarNode, body);
    els.preview.innerHTML = "";
    els.preview.appendChild(wrap);
  };

  /* ── JSON + curl ─────────────────────────────────────────────────────── */

  const highlight = (json) => {
    const escaped = escapeHtml(json);
    return escaped.replace(
      /("(?:\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
      (match) => {
        if (/^"/.test(match)) {
          if (/:$/.test(match)) return `<span class="k">${match.replace(/:$/, "")}</span>:`;
          return `<span class="s">${match}</span>`;
        }
        if (/true|false|null/.test(match)) return `<span class="b">${match}</span>`;
        return `<span class="n">${match}</span>`;
      }
    );
  };

  const paintJson = () => {
    const json = JSON.stringify(payload(), null, 2);
    if (els.jsonPane) els.jsonPane.innerHTML = highlight(json);
    if (els.curlPane) {
      const oneLine = JSON.stringify(payload());
      const curl = [
        "curl -X POST \"$WEBHOOK_URL\" \\",
        "  -H \"Content-Type: application/json\" \\",
        `  --data '${oneLine.replace(/'/g, "'\\''")}'`,
      ].join("\n");
      els.curlPane.textContent = curl;
    }
  };

  /* ── validation panel ────────────────────────────────────────────────── */

  const paintValidation = () => {
    if (!els.validatePane) return;
    const issues = validate();
    els.validatePane.innerHTML = "";
    if (!issues.length) {
      const ok = document.createElement("div");
      ok.className = "issue ok";
      ok.innerHTML = "<span class=\"mark\">✓</span><span>Within every Discord limit. Ready to send.</span>";
      els.validatePane.appendChild(ok);
    } else {
      issues.forEach((issue) => {
        const row = document.createElement("div");
        row.className = `issue${issue.level === "warn" ? " warn" : ""}`;
        row.innerHTML = `<span class="mark">${issue.level === "warn" ? "!" : "×"}</span><span>${escapeHtml(issue.text)}</span>`;
        row.style.cursor = "pointer";
        row.addEventListener("click", () => {
          const target = document.getElementById(issue.target);
          if (target) {
            target.scrollIntoView({ block: "center", behavior: "smooth" });
            target.focus({ preventScroll: true });
          }
        });
        els.validatePane.appendChild(row);
      });
    }
    const badge = $("#issueBadge");
    if (badge) {
      const errors = issues.filter((issue) => issue.level === "error").length;
      badge.textContent = errors ? `${errors} error${errors === 1 ? "" : "s"}` : issues.length ? `${issues.length} warning${issues.length === 1 ? "" : "s"}` : "clean";
      badge.style.color = errors ? "#fff" : "";
    }
  };

  /* ── field editor ────────────────────────────────────────────────────── */

  const paintFields = () => {
    if (!els.fields) return;
    const embed = current();
    els.fields.innerHTML = "";

    if (!embed.fields.length) {
      const empty = document.createElement("div");
      empty.className = "status-note";
      empty.style.padding = "14px 2px";
      empty.textContent = "No fields yet. Add one, or drop a template from the right.";
      els.fields.appendChild(empty);
    }

    embed.fields.forEach((field, index) => {
      const row = document.createElement("div");
      row.className = "embed-field";
      row.draggable = true;
      row.dataset.index = String(index);

      const head = document.createElement("div");
      head.className = "embed-field-head";
      head.innerHTML = `<span class="drag-handle" title="Drag to reorder">⠿ field ${String(index + 1).padStart(2, "0")}</span>`;

      const tools = document.createElement("div");
      tools.className = "tools";

      const toggle = document.createElement("label");
      toggle.className = "toggle";
      toggle.innerHTML = `<input type="checkbox" ${field.inline ? "checked" : ""} aria-label="Inline field"><span>inline</span>`;
      toggle.querySelector("input").addEventListener("change", (event) => {
        field.inline = event.target.checked;
        commit(false);
        paintFields();
      });

      const makeButton = (label, title, handler, disabled) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "icon-btn";
        button.textContent = label;
        button.title = title;
        button.disabled = Boolean(disabled);
        button.addEventListener("click", handler);
        return button;
      };

      tools.append(
        toggle,
        makeButton("↑", "Move up", () => moveField(index, -1), index === 0),
        makeButton("↓", "Move down", () => moveField(index, 1), index === embed.fields.length - 1),
        makeButton("dup", "Duplicate field", () => {
          embed.fields.splice(index + 1, 0, { ...field, name: field.name, value: field.value });
          commit(true);
        }, embed.fields.length >= MAX_FIELDS),
        makeButton("×", "Delete field", () => {
          embed.fields.splice(index, 1);
          commit(true);
        })
      );

      head.appendChild(tools);

      const name = document.createElement("input");
      name.className = "input";
      name.id = `field-${index}-name`;
      name.placeholder = "Field name";
      name.value = field.name;
      name.maxLength = 256;
      name.addEventListener("input", () => {
        field.name = name.value;
        commit(false);
      });

      const value = document.createElement("textarea");
      value.className = "textarea";
      value.id = `field-${index}-value`;
      value.placeholder = "Field value (markdown works)";
      value.value = field.value;
      value.style.minHeight = "64px";
      value.addEventListener("input", () => {
        field.value = value.value;
        commit(false);
      });

      const counter = document.createElement("div");
      counter.className = "counter";
      const paintCounter = () => {
        counter.textContent = `${field.name.length}/256 · ${field.value.length}/1024`;
        counter.classList.toggle("over", field.name.length > 256 || field.value.length > 1024);
      };
      paintCounter();
      name.addEventListener("input", paintCounter);
      value.addEventListener("input", paintCounter);

      row.append(head, name, value, counter);

      row.addEventListener("dragstart", (event) => {
        row.classList.add("dragging");
        event.dataTransfer.effectAllowed = "move";
        event.dataTransfer.setData("text/plain", String(index));
      });
      row.addEventListener("dragend", () => {
        row.classList.remove("dragging");
        $$(".embed-field", els.fields).forEach((node) => node.classList.remove("drop-target"));
      });
      row.addEventListener("dragover", (event) => {
        event.preventDefault();
        row.classList.add("drop-target");
      });
      row.addEventListener("dragleave", () => row.classList.remove("drop-target"));
      row.addEventListener("drop", (event) => {
        event.preventDefault();
        row.classList.remove("drop-target");
        const from = Number(event.dataTransfer.getData("text/plain"));
        const to = index;
        if (!Number.isInteger(from) || from === to) return;
        const [moved] = embed.fields.splice(from, 1);
        embed.fields.splice(to, 0, moved);
        commit(true);
      });

      els.fields.appendChild(row);
    });

    const addButton = $("#addField");
    if (addButton) addButton.disabled = embed.fields.length >= MAX_FIELDS;
    const count = $("#fieldCount");
    if (count) count.textContent = `${embed.fields.length}/${MAX_FIELDS}`;
  };

  const moveField = (index, delta) => {
    const embed = current();
    const target = index + delta;
    if (target < 0 || target >= embed.fields.length) return;
    const [moved] = embed.fields.splice(index, 1);
    embed.fields.splice(target, 0, moved);
    commit(true);
  };

  /* ── embed tabs ──────────────────────────────────────────────────────── */

  const paintTabs = () => {
    if (!els.tabs) return;
    els.tabs.innerHTML = "";
    state.embeds.forEach((embed, index) => {
      const tab = document.createElement("button");
      tab.type = "button";
      tab.className = "embed-tab";
      tab.setAttribute("role", "tab");
      tab.setAttribute("aria-selected", String(index === state.active));
      const label = embed.title.trim() ? clamp(embed.title.trim(), 18) : `Embed ${index + 1}`;
      tab.innerHTML = `<span>${escapeHtml(label)}</span>${state.embeds.length > 1 ? '<span class="x" title="Remove embed">×</span>' : ""}`;
      tab.addEventListener("click", (event) => {
        if (event.target.classList.contains("x")) {
          event.stopPropagation();
          removeEmbed(index);
          return;
        }
        state.active = index;
        paintInputs();
        paint();
      });
      els.tabs.appendChild(tab);
    });

    const add = document.createElement("button");
    add.type = "button";
    add.className = "embed-tab";
    add.textContent = "+ embed";
    add.disabled = state.embeds.length >= MAX_EMBEDS;
    add.title = state.embeds.length >= MAX_EMBEDS ? "Three embeds is the Discord ceiling" : "Add another embed";
    add.addEventListener("click", () => {
      state.embeds.push(blankEmbed());
      state.active = state.embeds.length - 1;
      commit(true);
      paintInputs();
      say(`embed ${state.active + 1} added`);
    });
    els.tabs.appendChild(add);

    if (els.activeLabel) els.activeLabel.textContent = `editing embed ${state.active + 1} of ${state.embeds.length}`;
  };

  const removeEmbed = (index) => {
    if (state.embeds.length === 1) {
      state.embeds[0] = blankEmbed();
      state.active = 0;
    } else {
      state.embeds.splice(index, 1);
      state.active = Math.max(0, Math.min(state.active, state.embeds.length - 1));
    }
    commit(true);
    paintInputs();
    paint();
    say("embed removed");
  };

  /* ── inputs ──────────────────────────────────────────────────────────── */

  const bindInput = (element, getter, setter, counterNode, limit) => {
    if (!element) return;
    const paintCounter = () => {
      if (!counterNode) return;
      const value = String(getter() || "");
      counterNode.textContent = limit ? `${value.length}/${limit}` : String(value.length);
      counterNode.classList.toggle("over", Boolean(limit) && value.length > limit);
    };
    element.value = getter() || "";
    paintCounter();
    if (element.dataset.bound) return;
    element.dataset.bound = "1";
    element.addEventListener("input", () => {
      setter(element.value);
      paintCounter();
      commit(false);
    });
  };

  const paintInputs = () => {
    const embed = current();
    bindInput(els.content, () => state.content, (value) => { state.content = value; }, els.contentCount, 2000);
    bindInput(els.username, () => state.username, (value) => { state.username = value; });
    bindInput(els.avatar, () => state.avatar, (value) => { state.avatar = value; });

    bindInput($("#e-title"), () => current().title, (value) => { current().title = value; }, $("#count-title"), 256);
    bindInput($("#e-description"), () => current().description, (value) => { current().description = value; }, $("#count-description"), 4096);
    bindInput($("#e-url"), () => current().url, (value) => { current().url = value; });
    bindInput($("#e-thumbnail"), () => current().thumbnail, (value) => { current().thumbnail = value; });
    bindInput($("#e-image"), () => current().image, (value) => { current().image = value; });
    bindInput($("#e-author-name"), () => current().author.name, (value) => { current().author.name = value; }, $("#count-author"), 256);
    bindInput($("#e-author-icon"), () => current().author.icon, (value) => { current().author.icon = value; });
    bindInput($("#e-author-url"), () => current().author.url, (value) => { current().author.url = value; });
    bindInput($("#e-footer-text"), () => current().footer.text, (value) => { current().footer.text = value; }, $("#count-footer"), 2048);
    bindInput($("#e-footer-icon"), () => current().footer.icon, (value) => { current().footer.icon = value; });

    if (els.colorInput) {
      els.colorInput.value = embed.color;
      if (!els.colorInput.dataset.bound) {
        els.colorInput.dataset.bound = "1";
        els.colorInput.addEventListener("input", () => {
          const value = els.colorInput.value.trim();
          if (value && !value.startsWith("#")) els.colorInput.value = `#${value.replace(/^#/, "")}`;
          current().color = els.colorInput.value;
          commit(false);
          paintSwatches();
        });
      }
    }

    const timestamp = $("#e-timestamp");
    if (timestamp) {
      timestamp.checked = embed.timestamp;
      if (!timestamp.dataset.bound) {
        timestamp.dataset.bound = "1";
        timestamp.addEventListener("change", () => {
          current().timestamp = timestamp.checked;
          commit(false);
        });
      }
    }

    paintSwatches();
  };

  const paintSwatches = () => {
    if (!els.swatches) return;
    els.swatches.innerHTML = "";
    PALETTE.forEach((color) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "swatch";
      button.style.background = color;
      button.title = color;
      button.setAttribute("aria-label", `Use ${color}`);
      button.setAttribute("aria-pressed", String(current().color.toLowerCase() === color.toLowerCase()));
      button.addEventListener("click", () => {
        current().color = color;
        if (els.colorInput) els.colorInput.value = color;
        commit(false);
        paintSwatches();
      });
      els.swatches.appendChild(button);
    });
  };

  /* ── undo / redo / autosave ──────────────────────────────────────────── */

  const snapshot = () => JSON.stringify(state);

  const commit = (structural) => {
    const now = snapshot();
    if (now !== lastSnapshot) {
      if (lastSnapshot) history.push(lastSnapshot);
      if (history.length > 80) history.shift();
      future = [];
      lastSnapshot = now;
    }
    paint();
    if (structural) paintFields();
    window.clearTimeout(structuralTimer);
    structuralTimer = window.setTimeout(() => {
      try {
        localStorage.setItem(AUTOSAVE, JSON.stringify({ saved: Date.now(), state: JSON.parse(now) }));
      } catch (error) {
        /* storage may be full or blocked; editing continues */
      }
    }, 400);
  };

  const undo = () => {
    if (!history.length) {
      say("nothing to undo");
      return;
    }
    future.push(snapshot());
    state = JSON.parse(history.pop());
    lastSnapshot = snapshot();
    paintInputs();
    paint();
    paintFields();
    say("undo");
  };

  const redo = () => {
    if (!future.length) {
      say("nothing to redo");
      return;
    }
    history.push(snapshot());
    state = JSON.parse(future.pop());
    lastSnapshot = snapshot();
    paintInputs();
    paint();
    paintFields();
    say("redo");
  };

  /* ── paint pipeline ──────────────────────────────────────────────────── */

  const paint = () => {
    paintTabs();
    paintPreview();
    paintJson();
    paintValidation();
    if (state.active >= state.embeds.length) state.active = state.embeds.length - 1;
  };

  /* ── templates ───────────────────────────────────────────────────────── */

  const field = (name, value, inline = true) => ({ name, value, inline });

  const TEMPLATES = {
    lookup() {
      const embed = blankEmbed();
      embed.color = "#ffffff";
      embed.author.name = "0SWALD";
      embed.title = "vanitycheck · matrix";
      embed.url = "";
      embed.description = "**Resolved** `discord.gg/matrix` · public server\n> 41,208 members · 6,942 online · created 2019-04-11";
      embed.fields = [
        field("STATE", "resolved · public", true),
        field("VANITY", "custom · edgeless", true),
        field("OWNER", "hidden (privacy settings)", true),
        field("FEATURES", "ANIMATED_ICON · BANNER · COMMUNITY", false),
        field("RISK", "none observed in public metadata", false),
      ];
      embed.footer.text = "source: invite API · local computation";
      embed.timestamp = true;
      return { content: "", username: "0SWALD", avatar: "", embeds: [embed], active: 0 };
    },
    alert() {
      const embed = blankEmbed();
      embed.color = "#ffffff";
      embed.author.name = "WATCHTOWER";
      embed.title = "Vanity released";
      embed.description = "`discord.gg/void` just became available. First seen: 2026-11-15 04:12 UTC.";
      embed.fields = [
        field("CODE", "`void`", true),
        field("WATCHED", "6h 12m", true),
        field("ACTION", "claim from Server Settings → Vanity URL", false),
      ];
      embed.footer.text = "poll interval 60s · cached 30s";
      embed.timestamp = true;
      return { content: "<@&000000000000000000> watchtower event", username: "0SWALD", avatar: "", embeds: [embed], active: 0 };
    },
    access() {
      const embed = blankEmbed();
      embed.color = "#ffffff";
      embed.title = "Access refused";
      embed.description = "This instance is private. Your Discord ID is not on the operator's allow-list, so no data was fetched and no command was executed.";
      embed.fields = [field("REQUEST", "`vanitycheck hex`", true), field("ACTION", "ask the operator to approve you", false)];
      embed.footer.text = "logged to the audit feed";
      return { content: "", username: "0SWALD", avatar: "", embeds: [embed], active: 0 };
    },
    pack() {
      const one = blankEmbed();
      one.color = "#ffffff";
      one.title = "Part 1 · identity";
      one.description = "What the target presents to the world.";
      one.fields = [field("HANDLE", "`@greed`", true), field("SURFACES", "7 checked · 4 free", true), field("PIVOT", "`greed.dev`", true)];
      const two = blankEmbed();
      two.color = "#8e8e8e";
      two.title = "Part 2 · infrastructure";
      two.description = "Where those accounts point.";
      two.fields = [field("ASN", "AS13335", true), field("NS", "a.iana-servers.net", true), field("CERT", "issued 2026-09-02", true)];
      const three = blankEmbed();
      three.color = "#4f545c";
      three.title = "Part 3 · next moves";
      three.description = "Three follow-ups worth checking next.";
      three.fields = [field("01", "check certificate first-seen", false), field("02", "map redirect chain", false), field("03", "compare mirrors", false)];
      return { content: "**Briefing pack** · collected 2026-11-15", username: "0SWALD", avatar: "", embeds: [one, two, three], active: 0 };
    },
    minimal() {
      const embed = blankEmbed();
      embed.color = "#ffffff";
      embed.description = "One line of text, no title.";
      return { content: "", username: "0SWALD", avatar: "", embeds: [embed], active: 0 };
    },
  };

  $$("[data-template]").forEach((button) => {
    button.addEventListener("click", () => {
      const name = button.dataset.template;
      const build = TEMPLATES[name];
      if (!build) return;
      state = build();
      history = [];
      future = [];
      lastSnapshot = snapshot();
      paintInputs();
      paint();
      paintFields();
      say(`template loaded · ${name}`);
    });
  });

  /* ── actions ─────────────────────────────────────────────────────────── */

  const bind = (selector, handler) => {
    const element = $(selector);
    if (element) element.addEventListener("click", handler);
  };

  bind("#undo", undo);
  bind("#redo", redo);

  bind("#addField", () => {
    const embed = current();
    if (embed.fields.length >= MAX_FIELDS) {
      say(`field ceiling reached (${MAX_FIELDS})`);
      return;
    }
    embed.fields.push({ name: "", value: "", inline: true });
    commit(true);
  });

  bind("#copyJson", async () => {
    const ok = await window.copyText(JSON.stringify(payload(), null, 2));
    say(ok ? "payload JSON copied" : "copy failed; use the JSON tab", true);
  });

  bind("#copyEmbed", async () => {
    const embed = rawEmbed(current());
    const ok = await window.copyText(JSON.stringify(embed, null, 2));
    say(ok ? `embed ${state.active + 1} JSON copied` : "copy failed", true);
  });

  bind("#copyCurl", async () => {
    const ok = await window.copyText(els.curlPane ? els.curlPane.textContent : "");
    say(ok ? "webhook call copied; replace $WEBHOOK_URL" : "copy failed", true);
  });

  bind("#copyPlain", async () => {
    const embed = current();
    const lines = [];
    if (embed.title) lines.push(`## ${embed.title}`);
    if (embed.description) lines.push("", embed.description);
    embed.fields.forEach((field) => lines.push("", `**${field.name}**`, field.value));
    if (embed.footer.text) lines.push("", `_${embed.footer.text}_`);
    const ok = await window.copyText(lines.join("\n").trim());
    say(ok ? "plain text copied" : "copy failed", true);
  });

  bind("#exportFile", () => {
    const data = JSON.stringify({ studio: 1, ...payload() }, null, 2);
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([data], { type: "application/json" }));
    link.download = "embed-draft.json";
    link.click();
    URL.revokeObjectURL(link.href);
    say("draft downloaded");
  });

  bind("#clearStudio", () => {
    state = blankState();
    history = [];
    future = [];
    lastSnapshot = "";
    paintInputs();
    paint();
    paintFields();
    say("studio cleared", true);
  });

  bind("#importRun", () => {
    if (!els.importBox) return;
    const raw = els.importBox.value.trim();
    if (!raw) {
      note(els.importNote, "paste a payload or an embed first");
      return;
    }
    try {
      const parsed = JSON.parse(raw);
      const source = Array.isArray(parsed) ? { embeds: parsed } : parsed.embeds ? parsed : { embeds: [parsed] };
      const embeds = (source.embeds || []).slice(0, MAX_EMBEDS).map((raw) => {
        const embed = blankEmbed();
        if (raw.author) {
          embed.author.name = raw.author.name || "";
          embed.author.icon = raw.author.icon_url || "";
          embed.author.url = raw.author.url || "";
        }
        embed.title = raw.title || "";
        embed.url = raw.url || "";
        embed.description = raw.description || "";
        if (typeof raw.color === "number") embed.color = `#${raw.color.toString(16).padStart(6, "0")}`;
        else if (typeof raw.color === "string" && HEX.test(raw.color)) embed.color = raw.color;
        embed.fields = (raw.fields || []).slice(0, MAX_FIELDS).map((field) => ({ name: field.name || "", value: field.value || "", inline: Boolean(field.inline) }));
        embed.thumbnail = raw.thumbnail && raw.thumbnail.url ? raw.thumbnail.url : "";
        embed.image = raw.image && raw.image.url ? raw.image.url : "";
        if (raw.footer) {
          embed.footer.text = raw.footer.text || "";
          embed.footer.icon = raw.footer.icon_url || "";
        }
        embed.timestamp = Boolean(raw.timestamp) || Boolean(raw.footer && raw.footer.text && raw.timestamp);
        return embed;
      });
      state = {
        content: source.content || "",
        username: source.username || "",
        avatar: source.avatar_url || "",
        embeds: embeds.length ? embeds : [blankEmbed()],
        active: 0,
      };
      history = [];
      future = [];
      lastSnapshot = snapshot();
      paintInputs();
      paint();
      paintFields();
      note(els.importNote, `imported ${state.embeds.length} embed(s)`);
      say("payload imported");
    } catch (error) {
      note(els.importNote, "that is not valid JSON; check the braces and quotes");
    }
  });

  if (els.importBox) {
    els.importBox.addEventListener("paste", () => {
      window.setTimeout(() => note(els.importNote, "ready · press import"), 0);
    });
  }

  /* tabs inside the right column */
  $$(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      $$(".tab").forEach((other) => other.setAttribute("aria-selected", String(other === tab)));
      $$(".tab-panel").forEach((panel) => panel.classList.toggle("active", panel.dataset.panel === tab.dataset.tab));
    });
  });

  document.addEventListener("keydown", (event) => {
    const mod = event.metaKey || event.ctrlKey;
    if (!mod) return;
    if (event.key.toLowerCase() === "z") {
      event.preventDefault();
      if (event.shiftKey) redo();
      else undo();
    } else if (event.key.toLowerCase() === "y") {
      event.preventDefault();
      redo();
    }
  });

  /* ── boot ────────────────────────────────────────────────────────────── */

  const restore = () => {
    try {
      const saved = localStorage.getItem(AUTOSAVE);
      if (!saved) return false;
      const parsed = JSON.parse(saved);
      if (!parsed || !parsed.state || !Array.isArray(parsed.state.embeds)) return false;
      state = parsed.state;
      state.embeds = state.embeds.slice(0, MAX_EMBEDS).map((embed) => ({ ...blankEmbed(), ...embed, author: { ...blankEmbed().author, ...(embed.author || {}) }, footer: { ...blankEmbed().footer, ...(embed.footer || {}) } }));
      if (!state.embeds.length) state.embeds = [blankEmbed()];
      state.active = Math.min(state.active || 0, state.embeds.length - 1);
      return true;
    } catch (error) {
      return false;
    }
  };

  const restored = restore();
  lastSnapshot = snapshot();
  paintInputs();
  paint();
  paintFields();
  if (restored) {
    say("restored your last draft · saved locally", false);
  } else {
    say("new draft · autosaves in this browser", false);
  }
})();
