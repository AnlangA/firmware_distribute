(() => {
  const STORAGE_KEY = "fd_auth_basic";
  let authHeader = sessionStorage.getItem(STORAGE_KEY) || "";
  let currentUser = null;
  let currentOffset = 0;
  const pageLimit = 30;
  let selectedUploadFiles = [];

  const $ = (id) => document.getElementById(id);

  function showToast(msg) {
    const t = $("toast");
    t.textContent = msg;
    t.classList.remove("hidden");
    setTimeout(() => t.classList.add("hidden"), 2400);
  }

  function formatBytes(bytes) {
    if (!bytes) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    const idx = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return (bytes / Math.pow(1024, idx)).toFixed(idx === 0 ? 0 : 2) + " " + units[idx];
  }

  function formatTime(iso) {
    if (!iso) return "-";
    const d = new Date(iso);
    return isNaN(d.getTime()) ? iso : d.toLocaleString();
  }

  function escapeHtml(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  async function apiFetch(url, options = {}) {
    const headers = Object.assign({}, options.headers || {}, {
      Authorization: authHeader,
    });
    const resp = await fetch(url, { ...options, headers });
    if (resp.status === 401) {
      logout();
      throw new Error("认证失效，请重新登录");
    }
    return resp;
  }

  function hasScope(scope) {
    if (!currentUser) return false;
    return currentUser.scopes.includes("admin") || currentUser.scopes.includes(scope);
  }

  async function tryLogin(ak, sk) {
    const token = btoa(`${ak}:${sk}`);
    const header = `Basic ${token}`;
    const resp = await fetch("/api/v1/auth/me", {
      headers: { Authorization: header },
    });
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data?.error?.message || "AccessKey ID 或 Secret 无效");
    }
    const me = await resp.json();
    authHeader = header;
    sessionStorage.setItem(STORAGE_KEY, header);
    currentUser = me;
    enterApp();
  }

  function logout() {
    authHeader = "";
    currentUser = null;
    sessionStorage.removeItem(STORAGE_KEY);
    $("app-shell").classList.add("hidden");
    $("login-overlay").classList.remove("hidden");
  }

  function enterApp() {
    $("login-overlay").classList.add("hidden");
    $("app-shell").classList.remove("hidden");
    $("user-name").textContent = currentUser.name;
    $("user-scopes").innerHTML = currentUser.scopes
      .map((s) => `<span class="badge badge-${escapeHtml(s)}">${escapeHtml(s)}</span>`)
      .join(" ");

    $("btn-open-upload").classList.toggle("hidden", !hasScope("write"));

    const nav = $("main-nav");
    nav.innerHTML = "";
    const tabs = [];
    if (hasScope("read")) {
      tabs.push({ id: "files", label: "文件管理" });
      tabs.push({ id: "projects", label: "项目概览" });
    }
    if (hasScope("admin")) {
      tabs.push({ id: "keys", label: "密钥管理" });
      tabs.push({ id: "audit", label: "审计日志" });
    }

    tabs.forEach((tab, idx) => {
      const btn = document.createElement("button");
      btn.className = `nav-tab ${idx === 0 ? "active" : ""}`;
      btn.textContent = tab.label;
      btn.dataset.tab = tab.id;
      btn.onclick = () => switchTab(tab.id);
      nav.appendChild(btn);
    });

    if (tabs.length > 0) {
      switchTab(tabs[0].id);
    } else if (hasScope("write")) {
      switchTab("write-only");
    }
  }

  function switchTab(tabId) {
    document.querySelectorAll(".nav-tab").forEach((b) => {
      b.classList.toggle("active", b.dataset.tab === tabId);
    });
    document.querySelectorAll(".tab-panel").forEach((p) => {
      p.classList.toggle("hidden", p.id !== `tab-${tabId}`);
    });
    if (tabId === "files") {
      loadProjectFilter();
      loadFiles();
    } else if (tabId === "projects") {
      loadProjects();
    } else if (tabId === "keys") {
      loadKeys();
    } else if (tabId === "audit") {
      loadAuditLogs();
    }
  }

  async function loadProjectFilter() {
    const resp = await apiFetch("/api/v1/projects");
    if (!resp.ok) return;
    const projects = await resp.json();
    const sel = $("filter-project");
    const prev = sel.value;
    sel.innerHTML = `<option value="">全部项目</option>` + projects
      .map((p) => `<option value="${escapeHtml(p.slug)}">${escapeHtml(p.name)} (${p.file_count})</option>`)
      .join("");
    sel.value = prev;
  }

  async function loadFiles() {
    const params = new URLSearchParams();
    const q = $("filter-q").value.trim();
    const project = $("filter-project").value;
    const fileType = $("filter-type").value;
    const ext = $("filter-ext").value.trim();
    const sort = $("filter-sort").value;
    if (q) params.set("q", q);
    if (project) params.set("project", project);
    if (fileType) params.set("file_type", fileType);
    if (ext) params.set("ext", ext);
    if (sort) params.set("sort", sort);
    params.set("limit", String(pageLimit));
    params.set("offset", String(currentOffset));

    const resp = await apiFetch(`/api/v1/files?${params.toString()}`);
    if (!resp.ok) return;
    const data = await resp.json();
    const tbody = $("files-tbody");
    $("files-empty").classList.toggle("hidden", data.items.length > 0);
    $("files-total").textContent = `共 ${data.total} 个文件（当前 ${data.offset + 1}-${Math.min(data.offset + data.items.length, data.total)}）`;
    $("btn-prev-page").disabled = currentOffset <= 0;
    $("btn-next-page").disabled = currentOffset + data.items.length >= data.total;

    const canDelete = hasScope("write") || hasScope("admin");
    tbody.innerHTML = data.items
      .map((f) => {
        const shortHash = f.sha256.slice(0, 12) + "...";
        return `<tr>
          <td>
            <strong>${escapeHtml(f.file_name)}</strong>
            ${f.summary ? `<div class="muted">${escapeHtml(f.summary)}</div>` : ""}
          </td>
          <td><span class="badge">${escapeHtml(f.project_name)}</span></td>
          <td>${escapeHtml(f.file_type)}</td>
          <td>${escapeHtml(f.version || "-")}</td>
          <td>${formatBytes(f.file_size)}</td>
          <td>
            <code title="${escapeHtml(f.sha256)}">${escapeHtml(shortHash)}</code>
            <button class="btn btn-ghost btn-sm" data-copy="${escapeHtml(f.sha256)}">复制</button>
          </td>
          <td>${formatTime(f.created_at)}</td>
          <td class="inline-group">
            <button class="btn btn-secondary btn-sm" data-download="${escapeHtml(f.id)}" data-filename="${escapeHtml(f.file_name)}">下载</button>
            ${canDelete ? `<button class="btn btn-danger btn-sm" data-del-file="${escapeHtml(f.id)}">删除</button>` : ""}
          </td>
        </tr>`;
      })
      .join("");
  }

  async function downloadFile(id, filename) {
    showToast(`正在下载 ${filename}...`);
    const resp = await apiFetch(`/api/v1/files/${encodeURIComponent(id)}/download`);
    if (!resp.ok) {
      showToast("下载失败");
      return;
    }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  async function deleteFile(id) {
    if (!confirm("确定永久删除该文件吗？")) return;
    const resp = await apiFetch(`/api/v1/files/${encodeURIComponent(id)}`, { method: "DELETE" });
    if (resp.ok) {
      showToast("文件已删除");
      loadFiles();
    } else {
      showToast("删除失败");
    }
  }

  async function loadProjects() {
    const q = $("project-search").value.trim();
    const url = q ? `/api/v1/projects?q=${encodeURIComponent(q)}` : "/api/v1/projects";
    const resp = await apiFetch(url);
    if (!resp.ok) return;
    const projects = await resp.json();
    $("projects-grid").innerHTML = projects
      .map(
        (p) => `<div class="card project-card" data-proj-slug="${escapeHtml(p.slug)}">
          <h4>${escapeHtml(p.name)} ${p.is_public ? '<span class="badge">public</span>' : ""}</h4>
          <div class="muted">slug: <code>${escapeHtml(p.slug)}</code></div>
          <div style="margin-top:8px">文件数：<strong>${p.file_count}</strong> · 总大小：<strong>${formatBytes(p.total_size)}</strong></div>
          <div class="muted" style="margin-top:4px">更新：${formatTime(p.updated_at)}</div>
        </div>`
      )
      .join("");
  }

  async function loadKeys() {
    const resp = await apiFetch("/api/v1/keys");
    if (!resp.ok) return;
    const keys = await resp.json();
    $("keys-tbody").innerHTML = keys
      .map(
        (k) => `<tr>
          <td><strong>${escapeHtml(k.name)}</strong></td>
          <td><code>${escapeHtml(k.access_key_id)}</code></td>
          <td>${k.scopes.map((s) => `<span class="badge badge-${escapeHtml(s)}">${escapeHtml(s)}</span>`).join(" ")}</td>
          <td>${k.is_active ? '<span class="badge badge-read">有效</span>' : '<span class="badge badge-revoked">已吊销</span>'}</td>
          <td>${formatTime(k.created_at)}</td>
          <td>${formatTime(k.last_used_at)}</td>
          <td>${k.is_active && k.id !== currentUser.key_id ? `<button class="btn btn-danger btn-sm" data-revoke-key="${escapeHtml(k.id)}">吊销</button>` : "-"}</td>
        </tr>`
      )
      .join("");
  }

  async function loadAuditLogs() {
    const action = $("audit-action-filter").value;
    const url = action ? `/api/v1/audit-logs?action=${encodeURIComponent(action)}` : "/api/v1/audit-logs";
    const resp = await apiFetch(url);
    if (!resp.ok) return;
    const data = await resp.json();
    $("audit-tbody").innerHTML = data.items
      .map(
        (a) => `<tr>
          <td>${a.id}</td>
          <td>${escapeHtml(a.actor_name || a.actor_key_id || "-")}</td>
          <td><code>${escapeHtml(a.action)}</code></td>
          <td>${escapeHtml(a.target_type)} ${a.target_id ? `<code>${escapeHtml(a.target_id.slice(0, 12))}</code>` : ""}</td>
          <td>${escapeHtml(a.detail || "-")}</td>
          <td>${formatTime(a.created_at)}</td>
        </tr>`
      )
      .join("");
  }

  function openUploadModal() {
    selectedUploadFiles = [];
    $("selected-files-list").innerHTML = "";
    $("upload-error").classList.add("hidden");
    $("upload-progress-wrap").classList.add("hidden");
    $("upload-modal").classList.remove("hidden");
  }

  function setSelectedFiles(fileList) {
    selectedUploadFiles = Array.from(fileList);
    $("selected-files-list").innerHTML = selectedUploadFiles
      .map((f) => `<div>• ${escapeHtml(f.name)} (${formatBytes(f.size)})</div>`)
      .join("");
  }

  // Event listeners
  $("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("login-error").classList.add("hidden");
    try {
      await tryLogin($("login-ak").value.trim(), $("login-sk").value.trim());
    } catch (err) {
      $("login-error").textContent = err.message;
      $("login-error").classList.remove("hidden");
    }
  });

  $("btn-logout").onclick = logout;
  $("btn-theme").onclick = () => {
    const root = document.documentElement;
    const cur = root.getAttribute("data-theme");
    root.setAttribute("data-theme", cur === "dark" ? "light" : "dark");
  };

  $("btn-refresh-files").onclick = () => { currentOffset = 0; loadFiles(); };
  ["filter-project", "filter-type", "filter-sort"].forEach((id) => {
    $(id).onchange = () => { currentOffset = 0; loadFiles(); };
  });
  $("filter-q").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { currentOffset = 0; loadFiles(); }
  });
  $("btn-prev-page").onclick = () => { currentOffset = Math.max(0, currentOffset - pageLimit); loadFiles(); };
  $("btn-next-page").onclick = () => { currentOffset += pageLimit; loadFiles(); };

  $("files-tbody").addEventListener("click", (e) => {
    const copyBtn = e.target.closest("[data-copy]");
    if (copyBtn) {
      navigator.clipboard?.writeText(copyBtn.dataset.copy);
      showToast("SHA-256 已复制");
      return;
    }
    const dlBtn = e.target.closest("[data-download]");
    if (dlBtn) {
      downloadFile(dlBtn.dataset.download, dlBtn.dataset.filename);
      return;
    }
    const delBtn = e.target.closest("[data-del-file]");
    if (delBtn) {
      deleteFile(delBtn.dataset.delFile);
    }
  });

  $("btn-refresh-projects").onclick = loadProjects;
  $("projects-grid").addEventListener("click", (e) => {
    const card = e.target.closest("[data-proj-slug]");
    if (card) {
      $("filter-project").value = card.dataset.projSlug;
      currentOffset = 0;
      switchTab("files");
    }
  });

  $("btn-open-upload").onclick = openUploadModal;
  $("btn-write-only-upload").onclick = openUploadModal;
  $("btn-close-upload").onclick = () => $("upload-modal").classList.add("hidden");
  $("btn-cancel-upload").onclick = () => $("upload-modal").classList.add("hidden");
  $("btn-pick-files").onclick = () => $("upload-files-input").click();
  $("upload-files-input").onchange = (e) => setSelectedFiles(e.target.files);

  const dz = $("dropzone");
  dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("dragover"); });
  dz.addEventListener("dragleave", () => dz.classList.remove("dragover"));
  dz.addEventListener("drop", (e) => {
    e.preventDefault();
    dz.classList.remove("dragover");
    if (e.dataTransfer?.files?.length) setSelectedFiles(e.dataTransfer.files);
  });

  $("upload-form").addEventListener("submit", (e) => {
    e.preventDefault();
    if (!selectedUploadFiles.length) {
      $("upload-error").textContent = "请先选择至少一个文件";
      $("upload-error").classList.remove("hidden");
      return;
    }
    $("upload-error").classList.add("hidden");
    $("upload-progress-wrap").classList.remove("hidden");
    $("upload-progress-fill").style.width = "0%";
    $("upload-progress-text").textContent = "0%";
    $("btn-submit-upload").disabled = true;

    const form = new FormData();
    const project = $("upload-project").value.trim();
    const ftype = $("upload-type").value;
    const version = $("upload-version").value.trim();
    const tags = $("upload-tags").value.trim();
    const summary = $("upload-summary").value.trim();
    if (project) form.append("project", project);
    if (ftype) form.append("file_type", ftype);
    if (version) form.append("version", version);
    if (tags) form.append("tags", tags);
    if (summary) form.append("summary", summary);
    selectedUploadFiles.forEach((f) => form.append("file", f));

    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/v1/files");
    xhr.setRequestHeader("Authorization", authHeader);
    xhr.upload.onprogress = (ev) => {
      if (ev.lengthComputable) {
        const pct = Math.round((ev.loaded / ev.total) * 100);
        $("upload-progress-fill").style.width = pct + "%";
        $("upload-progress-text").textContent = pct + "%";
      }
    };
    xhr.onload = () => {
      $("btn-submit-upload").disabled = false;
      if (xhr.status >= 200 && xhr.status < 300) {
        $("upload-modal").classList.add("hidden");
        showToast("上传成功");
        if (hasScope("read")) {
          loadProjectFilter();
          loadFiles();
        }
      } else {
        let msg = "上传失败";
        try { msg = JSON.parse(xhr.responseText)?.error?.message || msg; } catch {}
        $("upload-error").textContent = msg;
        $("upload-error").classList.remove("hidden");
      }
    };
    xhr.onerror = () => {
      $("btn-submit-upload").disabled = false;
      $("upload-error").textContent = "网络错误";
      $("upload-error").classList.remove("hidden");
    };
    xhr.send(form);
  });

  $("btn-open-create-key").onclick = () => {
    $("created-key-result").classList.add("hidden");
    $("create-key-error").classList.add("hidden");
    $("create-key-form").reset();
    $("key-modal").classList.remove("hidden");
  };
  $("btn-close-key-modal").onclick = () => $("key-modal").classList.add("hidden");
  $("btn-cancel-key-modal").onclick = () => $("key-modal").classList.add("hidden");

  $("create-key-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("create-key-error").classList.add("hidden");
    const name = $("new-key-name").value.trim();
    const scopes = Array.from(document.querySelectorAll('#create-key-form input[name="scope"]:checked'))
      .map((el) => el.value);
    const resp = await apiFetch("/api/v1/keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, scopes }),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      $("create-key-error").textContent = data?.error?.message || "创建失败";
      $("create-key-error").classList.remove("hidden");
      return;
    }
    $("res-ak").textContent = data.access_key_id;
    $("res-sk").textContent = data.access_key_secret;
    $("res-curl").textContent = `curl -u ${data.access_key_id}:${data.access_key_secret} -F "project=Motor_X1" -F "file=@firmware.bin" ${location.origin}/api/v1/files`;
    $("created-key-result").classList.remove("hidden");
    loadKeys();
  });

  $("keys-tbody").addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-revoke-key]");
    if (!btn) return;
    if (!confirm("确定吊销该密钥？吊销后立即失效。")) return;
    const resp = await apiFetch(`/api/v1/keys/${encodeURIComponent(btn.dataset.revokeKey)}`, {
      method: "DELETE",
    });
    if (resp.ok) {
      showToast("密钥已吊销");
      loadKeys();
    }
  });

  $("btn-refresh-audit").onclick = loadAuditLogs;
  $("audit-action-filter").onchange = loadAuditLogs;

  // Auto-login from sessionStorage
  if (authHeader) {
    fetch("/api/v1/auth/me", { headers: { Authorization: authHeader } })
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((me) => {
        currentUser = me;
        enterApp();
      })
      .catch(() => logout());
  }
})();
