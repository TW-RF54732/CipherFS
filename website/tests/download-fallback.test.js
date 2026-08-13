"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");

const elements = new Map();
function element(selector) {
  if (!elements.has(selector)) {
    elements.set(selector, {
      textContent: "",
      href: "",
      hidden: false,
      attributes: new Map(),
      setAttribute(name, value) { this.attributes.set(name, value); },
      removeAttribute(name) { this.attributes.delete(name); },
    });
  }
  return elements.get(selector);
}

const scriptPath = path.join(__dirname, "..", "assets", "js", "download.js");
const { hydrateRelease, buildReleaseData } = require(scriptPath);

global.document = { querySelector: element };
global.fetch = async () => { throw new Error("fixture network failure"); };

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
  console.log("Download fallback test passed.");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
