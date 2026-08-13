"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");

const elements = new Map();
function element(selector) {
  if (!elements.has(selector)) {
    const classes = new Set();
    elements.set(selector, {
      textContent: "",
      href: "",
      hidden: false,
      attributes: new Map(),
      listeners: new Map(),
      classList: {
        add(name) { classes.add(name); },
        remove(name) { classes.delete(name); },
        contains(name) { return classes.has(name); },
      },
      setAttribute(name, value) { this.attributes.set(name, value); },
      removeAttribute(name) { this.attributes.delete(name); },
      addEventListener(name, listener) { this.listeners.set(name, listener); },
    });
  }
  return elements.get(selector);
}

const scriptPath = path.join(__dirname, "..", "assets", "js", "download.js");
const { hydrateRelease, buildReleaseData, setupStarPrompt } = require(scriptPath);

global.document = { querySelector: element };
global.fetch = async () => { throw new Error("fixture network failure"); };
const scheduled = [];
global.window = {
  setTimeout(callback, delay) {
    scheduled.push({ callback, delay, cancelled: false });
    return scheduled.length - 1;
  },
  clearTimeout(id) {
    if (scheduled[id]) scheduled[id].cancelled = true;
  },
  requestAnimationFrame(callback) { callback(); },
};

(async () => {
  const releases = require("./fixtures/releases.json");
  const calculated = buildReleaseData(releases, "2026-08-14T00:00:00Z");
  assert.equal(calculated.featured.tag, "v3.2.0", "live calculation must select the newest stable installer");
  assert.equal(calculated.installer.download_count, 7);
  assert.equal(calculated.totals.installer_downloads, 31, "live total includes prereleases but excludes drafts");

  const originalWarn = console.warn;
  console.warn = () => {};
  try {
    await hydrateRelease();
  } finally {
    console.warn = originalWarn;
  }
  assert.equal(
    element("[data-installer-link]").href,
    "https://github.com/TW-RF54732/CipherFS/releases",
    "installer must fall back to the Releases page",
  );
  assert.equal(element("[data-download-stats]").hidden, true, "download counts must be hidden");
  assert.match(element("[data-release-version]").textContent, /GitHub Releases/);
  assert.match(element("[data-release-status]").textContent, /無法讀取版本資料/);
  setupStarPrompt();
  const prompt = element("[data-star-prompt]");
  element("[data-installer-link]").listeners.get("click")();
  assert.equal(scheduled[0].delay, 4500, "star prompt should appear 4.5 seconds after download");
  scheduled[0].callback();
  assert.equal(prompt.hidden, false, "star prompt should become visible");
  assert.equal(prompt.classList.contains("is-visible"), true);
  element("[data-star-prompt-close]").listeners.get("click")();
  assert.equal(prompt.classList.contains("is-visible"), false, "close button should dismiss the prompt");
  assert.equal(scheduled[1].delay, 550, "prompt should be hidden after its exit transition");
  scheduled[1].callback();
  assert.equal(prompt.hidden, true);
  console.log("Download fallback and star prompt tests passed.");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
