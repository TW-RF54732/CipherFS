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

function renderRelease(data, sourceLabel) {
  document.querySelector("[data-release-version]").textContent = `${data.featured.tag} · ${formatDate(data.featured.published_at)}`;
  document.querySelector("[data-installer-name]").textContent = data.installer.name;
  document.querySelector("[data-installer-size]").textContent = formatBytes(data.installer.size_bytes);
  document.querySelector("[data-installer-downloads]").textContent = formatDownloads(data.installer.download_count);
  document.querySelector("[data-total-downloads]").textContent = formatDownloads(data.totals.installer_downloads);
  document.querySelector("[data-download-stats]").hidden = false;
  document.querySelector("[data-installer-link]").href = data.installer.url;

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
}

async function fetchGitHubReleaseData() {
  const response = await fetch(RELEASES_API, {
    headers: { Accept: "application/vnd.github+json" }, cache: "no-store",
  });
  if (!response.ok) throw new Error(`GitHub API returned ${response.status}`);
  return buildReleaseData(await response.json());
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
  try {
    renderRelease(
      await fetchGitHubReleaseData(),
      "此頁資料由 GitHub Releases 即時取得並計算。重新整理可更新下載次數。",
    );
    return;
  } catch (liveError) {
    console.warn("CipherFS live release data unavailable:", liveError);
  }

  try {
    const snapshot = await fetchSnapshotReleaseData();
    renderRelease(snapshot, `GitHub API 暫時無法使用，目前顯示 ${formatDate(snapshot.generated_at)} 的發布快照。`);
  } catch (snapshotError) {
    document.querySelector("[data-release-version]").textContent = "前往 GitHub Releases 取得最新版本";
    document.querySelector("[data-installer-link]").href = RELEASES_FALLBACK;
    document.querySelector("[data-download-stats]").hidden = true;
    document.querySelector("[data-release-status]").textContent = "目前無法讀取版本資料；下載按鈕已改為前往 GitHub Releases。";
    console.warn("CipherFS release data fallback:", snapshotError);
  }
}

function setupStarPrompt() {
  const downloadButton = document.querySelector("[data-installer-link]");
  const prompt = document.querySelector("[data-star-prompt]");
  const closeButton = document.querySelector("[data-star-prompt-close]");
  if (!downloadButton || !prompt || !closeButton) return;

  let revealTimer = null;
  const hidePrompt = () => {
    if (revealTimer !== null) clearTimeout(revealTimer);
    revealTimer = null;
    prompt.classList.remove("is-visible");
    window.setTimeout(() => { prompt.hidden = true; }, 550);
  };

  downloadButton.addEventListener("click", () => {
    if (revealTimer !== null) clearTimeout(revealTimer);
    prompt.hidden = true;
    prompt.classList.remove("is-visible");
    revealTimer = window.setTimeout(() => {
      prompt.hidden = false;
      window.requestAnimationFrame(() => prompt.classList.add("is-visible"));
      revealTimer = null;
    }, 4500);
  });
  closeButton.addEventListener("click", hidePrompt);
}

if (typeof document !== "undefined") {
  hydrateRelease();
  setupStarPrompt();
}
if (typeof module !== "undefined" && module.exports) {
  module.exports = { hydrateRelease, buildReleaseData, formatBytes, formatDownloads, formatDate, setupStarPrompt };
}
