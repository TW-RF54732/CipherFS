"use strict";

const GITHUB_REPO = "TW-RF54732/CipherFS";
const LATEST_RELEASE_API = `https://api.github.com/repos/${GITHUB_REPO}/releases/latest`;
const ALL_RELEASES_API = `https://api.github.com/repos/${GITHUB_REPO}/releases?per_page=100`;

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "";
  const units = ["B", "KB", "MB", "GB"];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, exponent);
  return `${value.toFixed(value >= 10 || exponent === 0 ? 0 : 1)} ${units[exponent]}`;
}

function formatNumber(num) {
  return new Intl.NumberFormat("en-US").format(num);
}

function findAsset(assets, pattern) {
  return assets.find((asset) => pattern.test(asset.name));
}

async function fetchJson(url) {
  const response = await fetch(url, {
    headers: {
      Accept: "application/vnd.github+json"
    }
  });

  if (!response.ok) {
    throw new Error(`GitHub API error: ${response.status}`);
  }

  return response.json();
}

function updateLink(selector, href, fallbackHref) {
  const element = document.querySelector(selector);
  if (!element) return;

  if (href) {
    element.href = href;
    element.removeAttribute("aria-disabled");
  } else if (fallbackHref) {
    element.href = fallbackHref;
    element.removeAttribute("aria-disabled");
  } else {
    element.setAttribute("aria-disabled", "true");
  }
}

function setText(selector, text) {
  const element = document.querySelector(selector);
  if (element && text !== undefined && text !== null) {
    element.textContent = text;
  }
}

function setDetail(selector, name, size) {
  const text = [name, formatBytes(size)].filter(Boolean).join(" · ");
  if (text) {
    setText(selector, text);
  }
}

function initStarPrompt() {
  const prompt = document.querySelector("[data-star-prompt]");
  const closeBtn = document.querySelector("[data-star-prompt-close]");
  const installerLink = document.querySelector("[data-installer-link]");

  if (!prompt || !installerLink) return;

  const storageKey = "cipherfs_star_prompt_dismissed";

  function showPrompt() {
    if (sessionStorage.getItem(storageKey)) return;
    prompt.hidden = false;
    requestAnimationFrame(() => {
      prompt.classList.add("is-visible");
    });
  }

  function hidePrompt() {
    prompt.classList.remove("is-visible");
    sessionStorage.setItem(storageKey, "1");
    setTimeout(() => {
      prompt.hidden = true;
    }, 250);
  }

  installerLink.addEventListener("click", () => {
    setTimeout(showPrompt, 1200);
  });

  if (closeBtn) {
    closeBtn.addEventListener("click", hidePrompt);
  }
}

async function loadReleaseData() {
  const statusEl = document.querySelector("[data-release-status]");
  const statsContainer = document.querySelector("[data-download-stats]");

  try {
    const [latest, allReleases] = await Promise.all([
      fetchJson(LATEST_RELEASE_API),
      fetchJson(ALL_RELEASES_API).catch(() => [])
    ]);

    const assets = Array.isArray(latest.assets) ? latest.assets : [];

    const installerAsset = findAsset(assets, /setup.*\.exe$|\.msi$/i) || findAsset(assets, /\.exe$/i);
    const portableAsset = findAsset(assets, /portable.*\.zip$|win.*x64.*\.zip$/i);
    const linuxAsset = findAsset(assets, /linux.*\.tar\.(gz|xz)$|linux.*\.zip$/i);
    const checksumAsset = findAsset(assets, /sha256|checksum/i);
    const manifestAsset = findAsset(assets, /manifest/i);
    const minisignAsset = findAsset(assets, /\.minisig$/i);

    setText("[data-release-version]", latest.tag_name || latest.name || "Latest release");

    if (installerAsset) {
      updateLink("[data-installer-link]", installerAsset.browser_download_url, latest.html_url);
      setText("[data-installer-name]", installerAsset.name);
      setText("[data-installer-size]", formatBytes(installerAsset.size) || "Windows x64");

      if (typeof installerAsset.download_count === "number") {
        setText("[data-installer-downloads]", formatNumber(installerAsset.download_count));
      }
    } else {
      updateLink("[data-installer-link]", latest.html_url);
    }

    if (portableAsset) {
      updateLink("[data-portable-link]", portableAsset.browser_download_url, latest.html_url);
      setDetail("[data-portable-detail]", portableAsset.name, portableAsset.size);
    } else {
      updateLink("[data-portable-link]", latest.html_url);
    }

    if (linuxAsset) {
      updateLink("[data-linux-link]", linuxAsset.browser_download_url, latest.html_url);
      setDetail("[data-linux-detail]", linuxAsset.name, linuxAsset.size);
    } else {
      updateLink("[data-linux-link]", latest.html_url);
    }

    if (checksumAsset) {
      updateLink("[data-checksum-link]", checksumAsset.browser_download_url, latest.html_url);
    } else {
      updateLink("[data-checksum-link]", latest.html_url);
    }

    if (manifestAsset) {
      updateLink("[data-manifest-link]", manifestAsset.browser_download_url, latest.html_url);
    } else {
      updateLink("[data-manifest-link]", latest.html_url);
    }

    if (minisignAsset) {
      updateLink("[data-minisign-link]", minisignAsset.browser_download_url, latest.html_url);
    } else {
      updateLink("[data-minisign-link]", latest.html_url);
    }

    updateLink("[data-release-notes-link]", latest.html_url, `https://github.com/${GITHUB_REPO}/releases`);

    let totalDownloads = 0;
    if (Array.isArray(allReleases) && allReleases.length) {
      for (const release of allReleases) {
        if (!Array.isArray(release.assets)) continue;
        for (const asset of release.assets) {
          if (typeof asset.download_count === "number") {
            totalDownloads += asset.download_count;
          }
        }
      }
    } else if (installerAsset && typeof installerAsset.download_count === "number") {
      totalDownloads = installerAsset.download_count;
    }

    if (totalDownloads > 0) {
      setText("[data-total-downloads]", formatNumber(totalDownloads));
    }

    if (statsContainer) {
      statsContainer.hidden = false;
    }

    if (statusEl) {
      statusEl.hidden = true;
    }
  } catch (error) {
    if (statusEl) {
      statusEl.textContent = "無法即時取得 GitHub 發布資料，請點擊按鈕直接前往 GitHub Releases 下載。";
    }
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initStarPrompt();
  loadReleaseData();
});