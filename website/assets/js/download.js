"use strict";

const REPOSITORY = "TW-RF54732/CipherFS";
const RELEASES_API = `https://api.github.com/repos/${REPOSITORY}/releases?per_page=100`;
const RELEASES_FALLBACK = `https://github.com/${REPOSITORY}/releases`;
const ATTESTATIONS_URL = `https://github.com/${REPOSITORY}/attestations`;
const ASSET_NAMES = Object.freeze({
  installer: "CipherFS-Setup-x64.exe",
  portable: "cipherfs-windows-portable-x64.zip",
  linux: "cipherfs-linux-x64.tar.gz",
  checksum: "cipherfs-windows-x64.sha256",
  manifest: "cipherfs-windows-setup.manifest",
  minisign: "cipherfs-windows-setup.manifest.minisig",
});

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "Windows x64";
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB · Windows x64`;
}

function formatDownloads(value) {
  return new Intl.NumberFormat("zh-TW").format(value);
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return new Intl.DateTimeFormat("zh-TW", {
    year: "numeric", month: "long", day: "numeric", timeZone: "UTC",
  }).format(date);
}

function findAsset(release, name) {
  return release.assets?.find((asset) => asset.name === name) || null;
}

async function detectDevice(navigatorLike = typeof navigator !== "undefined" ? navigator : {}) {
  const userAgentData = navigatorLike.userAgentData;
  const platform = String(userAgentData?.platform || navigatorLike.platform || "").toLowerCase();
  const userAgent = String(navigatorLike.userAgent || "").toLowerCase();
  let architecture = "";

  if (typeof userAgentData?.getHighEntropyValues === "function") {
    try {
      const values = await userAgentData.getHighEntropyValues(["architecture", "bitness"]);
      architecture = `${values.architecture || ""} ${values.bitness || ""}`.toLowerCase();
    } catch (error) {
      console.warn("CipherFS device architecture detection unavailable:", error);
    }
  }

  const fingerprint = `${platform} ${userAgent} ${architecture}`;
  const isArm = /\b(arm|arm64|aarch64)\b/.test(fingerprint);
  const isWindows = /win/.test(platform) || /windows/.test(userAgent);
  const isMac = /mac/.test(platform) || /macintosh|iphone|ipad/.test(userAgent);
  const isLinux = /linux/.test(platform) || /linux/.test(userAgent);
  const isMobile = /android|iphone|ipad/.test(fingerprint);

  if (isWindows && isArm) return { os: "windows", arch: "arm64", available: false };
  if (isWindows) return { os: "windows", arch: "x64", available: true };
  if (isMac) return { os: "macos", arch: isArm ? "arm64" : "x64", available: false };
  if (isLinux && !isMobile && isArm) return { os: "linux", arch: "arm64", available: false };
  if (isLinux && !isMobile) return { os: "linux", arch: "x64", available: true };
  return { os: "other", arch: isArm ? "arm64" : "unknown", available: false };
}

function buildReleaseData(releases, generatedAt = new Date().toISOString()) {
  if (!Array.isArray(releases)) throw new Error("GitHub Releases response is invalid");
  const published = releases.filter((release) => !release.draft);
  const featured = published
    .filter((release) => !release.prerelease && findAsset(release, ASSET_NAMES.installer))
    .sort((left, right) => new Date(right.published_at) - new Date(left.published_at))[0];
  if (!featured) throw new Error(`No stable release contains ${ASSET_NAMES.installer}`);

  const installer = findAsset(featured, ASSET_NAMES.installer);
  const alternative = (name) => {
    const asset = findAsset(featured, name);
    return asset ? { name: asset.name, url: asset.browser_download_url, size_bytes: asset.size } : null;
  };
  const assetUrl = (name) => findAsset(featured, name)?.browser_download_url || null;
  const installerTotal = published.reduce(
    (total, release) => total + (findAsset(release, ASSET_NAMES.installer)?.download_count || 0), 0,
  );

  return {
    generated_at: generatedAt,
    source: "github-api",
    featured: {
      tag: featured.tag_name, channel: "stable",
      published_at: featured.published_at, release_url: featured.html_url,
    },
    installer: {
      name: installer.name, url: installer.browser_download_url,
      size_bytes: installer.size, download_count: installer.download_count,
    },
    totals: { installer_downloads: installerTotal },
    alternatives: {
      windows_portable: alternative(ASSET_NAMES.portable),
      linux_x64: alternative(ASSET_NAMES.linux),
    },
    verification: {
      checksum_url: assetUrl(ASSET_NAMES.checksum),
      manifest_url: assetUrl(ASSET_NAMES.manifest),
      minisign_url: assetUrl(ASSET_NAMES.minisign),
      attestation_url: ATTESTATIONS_URL,
    },
  };
}

function setLink(selector, url, disabled = false) {
  const element = document.querySelector(selector);
  if (!element) return;
  element.href = url || RELEASES_FALLBACK;
  if (disabled) element.setAttribute("aria-disabled", "true");
  else element.removeAttribute("aria-disabled");
}

function setRecommendationText(device, data) {
  const heading = document.querySelector("[data-platform-heading]");
  const intro = document.querySelector("[data-platform-intro]");
  const kicker = document.querySelector("[data-release-kicker]");
  const title = document.querySelector("[data-product-title]");
  const button = document.querySelector("[data-installer-link]");
  const buttonLabel = document.querySelector("[data-download-label]");
  const name = document.querySelector("[data-installer-name]");
  const size = document.querySelector("[data-installer-size]");

  if (device.os === "linux" && device.available && data.alternatives.linux_x64) {
    heading.textContent = "下載 CipherFS for Linux";
    intro.textContent = "已根據你的裝置推薦 Linux x64 壓縮檔。需要 Windows 版本時仍可從下方手動選擇。";
    kicker.textContent = "Recommended · Stable · Linux x64";
    title.textContent = "CipherFS for Linux";
    button.href = data.alternatives.linux_x64.url;
    buttonLabel.textContent = "下載 Linux x64 archive";
    name.textContent = data.alternatives.linux_x64.name;
    size.textContent = `${formatBytes(data.alternatives.linux_x64.size_bytes).replace(" · Windows x64", "")} · Linux x64 / FUSE 3`;
    return;
  }

  if (device.os === "windows" && device.available) {
    heading.textContent = "下載 CipherFS for Windows";
    intro.textContent = "已根據你的裝置推薦 Windows x64 Installer。檔案直接來自 CipherFS 的 GitHub Releases。";
    kicker.textContent = "Recommended · Stable · Windows x64";
    title.textContent = "CipherFS Installer";
    buttonLabel.textContent = "下載 Windows Installer";
    return;
  }

  const platformNames = { windows: "Windows ARM", macos: "macOS", linux: "Linux ARM", other: "此裝置" };
  const platformName = device.os === "linux" && device.available ? "Linux x64" : platformNames[device.os] || "此裝置";
  heading.textContent = `CipherFS 尚未提供 ${platformName} 版本`;
  intro.textContent = "目前只提供 Windows x64 與 Linux x64。請勿下載不相容的版本；下方仍保留所有可用檔案。";
  kicker.textContent = "Unsupported device · Available builds listed below";
  title.textContent = "此裝置目前沒有相容版本";
  button.href = RELEASES_FALLBACK;
  buttonLabel.textContent = "查看所有 GitHub Releases";
  name.textContent = "Windows x64 · Linux x64";
  size.textContent = "尚未提供此平台";
  const status = document.querySelector("[data-release-status]");
  status.textContent += " 未偵測到相容的正式版本，因此不會自動推薦下載。";
}

function renderRelease(data, sourceLabel, device) {
  document.querySelector("[data-release-version]").textContent = `${data.featured.tag} · ${formatDate(data.featured.published_at)}`;
  document.querySelector("[data-installer-name]").textContent = data.installer.name;
  document.querySelector("[data-installer-size]").textContent = formatBytes(data.installer.size_bytes);
  document.querySelector("[data-installer-downloads]").textContent = formatDownloads(data.installer.download_count);
  document.querySelector("[data-total-downloads]").textContent = formatDownloads(data.totals.installer_downloads);
  document.querySelector("[data-download-stats]").hidden = false;
  document.querySelector("[data-installer-link]").href = data.installer.url;

  setLink("[data-windows-link]", data.installer.url);
  setLink("[data-portable-link]", data.alternatives.windows_portable?.url, !data.alternatives.windows_portable);
  setLink("[data-linux-link]", data.alternatives.linux_x64?.url, !data.alternatives.linux_x64);
  setLink("[data-release-notes-link]", data.featured.release_url);
  setLink("[data-checksum-link]", data.verification.checksum_url, !data.verification.checksum_url);
  setLink("[data-manifest-link]", data.verification.manifest_url, !data.verification.manifest_url);
  setLink("[data-minisign-link]", data.verification.minisign_url, !data.verification.minisign_url);
  setLink("[data-attestation-link]", data.verification.attestation_url);

  if (data.alternatives.windows_portable?.size_bytes) {
    document.querySelector("[data-portable-detail]").textContent =
      `${formatBytes(data.alternatives.windows_portable.size_bytes).replace(" · Windows x64", "")} · 不修改 PATH、Registry 或 Explorer`;
  }
  if (data.alternatives.linux_x64?.size_bytes) {
    document.querySelector("[data-linux-detail]").textContent =
      `${formatBytes(data.alternatives.linux_x64.size_bytes).replace(" · Windows x64", "")} · Linux x64 / FUSE 3`;
  }
  document.querySelector("[data-release-status]").textContent = sourceLabel;
  setRecommendationText(device, data);
}

async function fetchGitHubReleaseData() {
  const releases = [];
  // Match the snapshot generator's pagination so historical totals stay consistent.
  for (let page = 1; page <= 10; page += 1) {
    const response = await fetch(`${RELEASES_API}&page=${page}`, {
      headers: { Accept: "application/vnd.github+json" }, cache: "no-store",
    });
    if (!response.ok) throw new Error(`GitHub API returned ${response.status}`);
    const batch = await response.json();
    if (!Array.isArray(batch)) throw new Error("GitHub Releases response is invalid");
    releases.push(...batch);
    if (batch.length < 100) break;
  }
  return buildReleaseData(releases);
}

async function fetchSnapshotReleaseData() {
  const response = await fetch("../data/release.json", {
    headers: { Accept: "application/json" }, cache: "no-cache",
  });
  if (!response.ok) throw new Error(`release snapshot returned ${response.status}`);
  const data = await response.json();
  if (!data?.featured?.tag || !data?.installer?.url) throw new Error("release snapshot is incomplete");
  return data;
}

async function hydrateRelease() {
  const device = await detectDevice();
  try {
    renderRelease(
      await fetchGitHubReleaseData(),
      "此頁資料由 GitHub Releases 即時取得並計算。重新整理可更新下載次數。",
      device,
    );
    return;
  } catch (liveError) {
    console.warn("CipherFS live release data unavailable:", liveError);
  }

  try {
    const snapshot = await fetchSnapshotReleaseData();
    renderRelease(snapshot, `GitHub API 暫時無法使用，目前顯示 ${formatDate(snapshot.generated_at)} 的發布快照。`, device);
  } catch (snapshotError) {
    document.querySelector("[data-release-version]").textContent = "前往 GitHub Releases 取得最新版本";
    document.querySelector("[data-installer-link]").href = RELEASES_FALLBACK;
    document.querySelector("[data-download-label]").textContent = "查看 GitHub Releases";
    document.querySelector("[data-installer-name]").textContent = "Windows x64 · Linux x64";
    document.querySelector("[data-installer-size]").textContent = "請到發布頁選擇檔案";
    document.querySelector("[data-download-stats]").hidden = true;
    document.querySelector("[data-release-status]").textContent = "目前無法讀取版本資料；下載按鈕已改為前往 GitHub Releases。";
    console.warn("CipherFS release data fallback:", snapshotError);
  }
}

function setupStarPrompt() {
  const links = Array.from(document.querySelectorAll(
    "[data-installer-link], [data-windows-link], [data-portable-link], [data-linux-link]",
  ));
  const prompt = document.querySelector("[data-star-prompt]");
  const closeButton = document.querySelector("[data-star-prompt-close]");
  if (!links.length || !prompt || !closeButton) return;

  let revealTimer = null;
  let dismissTimer = null;
  let remaining = 12000;
  let dismissStarted = 0;
  let hovered = false;
  let focused = false;
  let lastDownloadLink = null;
  const removers = [];

  function listen(target, type, handler) {
    target.addEventListener(type, handler);
    removers.push(() => target.removeEventListener(type, handler));
  }
  function clearTimers() {
    if (revealTimer !== null) window.clearTimeout(revealTimer);
    if (dismissTimer !== null) window.clearTimeout(dismissTimer);
    revealTimer = dismissTimer = null;
  }
  function hidePrompt() {
    clearTimers();
    const restoreFocus = prompt.contains(document.activeElement);
    prompt.hidden = true;
    prompt.classList.remove("is-visible", "is-inline");
    hovered = focused = false;
    if (restoreFocus && lastDownloadLink) lastDownloadLink.focus();
  }
  function resumeDismiss() {
    if (prompt.hidden || hovered || focused || dismissTimer !== null) return;
    dismissStarted = Date.now();
    dismissTimer = window.setTimeout(hidePrompt, remaining);
  }
  function pauseDismiss() {
    if (dismissTimer === null) return;
    window.clearTimeout(dismissTimer);
    dismissTimer = null;
    remaining = Math.max(0, remaining - (Date.now() - dismissStarted));
  }
  function isActualDownload(link) {
    if (link.getAttribute("aria-disabled") === "true") return false;
    try {
      const url = new URL(link.href);
      const filename = decodeURIComponent(url.pathname.split("/").pop());
      return url.origin === "https://github.com"
        && url.pathname.startsWith(`/${REPOSITORY}/releases/download/`)
        && [ASSET_NAMES.installer, ASSET_NAMES.portable, ASSET_NAMES.linux].includes(filename);
    } catch {
      return false;
    }
  }
  function avoidCoveringFocus() {
    if (prompt.hidden || prompt.contains(document.activeElement)) return;
    const active = document.activeElement;
    if (!active || active === document.body || typeof active.getBoundingClientRect !== "function") return;
    const panel = prompt.getBoundingClientRect();
    const control = active.getBoundingClientRect();
    if (panel.left < control.right && panel.right > control.left
        && panel.top < control.bottom && panel.bottom > control.top) {
      prompt.classList.add("is-inline");
    }
  }
  for (const link of links) {
    listen(link, "click", () => {
      if (!isActualDownload(link)) return;
      hidePrompt();
      lastDownloadLink = link;
      remaining = 12000;
      revealTimer = window.setTimeout(() => {
        revealTimer = null;
        prompt.hidden = false;
        prompt.classList.add("is-visible");
        avoidCoveringFocus();
        resumeDismiss();
      }, 4500);
    });
  }
  listen(closeButton, "click", hidePrompt);
  listen(prompt, "mouseenter", () => { hovered = true; pauseDismiss(); });
  listen(prompt, "mouseleave", () => { hovered = false; resumeDismiss(); });
  listen(prompt, "focusin", () => { focused = true; pauseDismiss(); });
  listen(prompt, "focusout", (event) => {
    focused = prompt.contains(event.relatedTarget);
    if (!focused) resumeDismiss();
  });
  listen(document, "focusin", avoidCoveringFocus);
  listen(document, "keydown", (event) => {
    if (event.key === "Escape" && !prompt.hidden) hidePrompt();
  });
  listen(window, "scroll", avoidCoveringFocus);
  listen(window, "resize", avoidCoveringFocus);
  listen(window, "pagehide", hidePrompt);
  // A fresh page owns fresh timers; no storage or remembered display count.
  return () => { hidePrompt(); removers.forEach((remove) => remove()); };
}

if (typeof document !== "undefined") {
  hydrateRelease();
  setupStarPrompt();
}
if (typeof module !== "undefined" && module.exports) {
  module.exports = { hydrateRelease, buildReleaseData, detectDevice, formatBytes, formatDownloads, formatDate, setRecommendationText, setupStarPrompt };
}
