"use strict";

const assert = require("node:assert/strict");
const { hydrateRelease, buildReleaseData, detectDevice, setRecommendationText, setupStarPrompt } = require("../assets/js/download.js");
const releases = require("./fixtures/releases.json");
const snapshot = require("../data/release.json");
const fallback = "https://github.com/TW-RF54732/CipherFS/releases";

function eventTarget() {
  const listeners = new Map();
  return {
    addEventListener(type, fn) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type).add(fn);
    },
    removeEventListener(type, fn) { listeners.get(type)?.delete(fn); },
    emit(type, event = {}) { for (const fn of listeners.get(type) || []) fn(event); },
  };
}
const elements = new Map();
function element(selector) {
  if (!elements.has(selector)) {
    const classes = new Set();
    const attributes = new Map();
    const target = {
      ...eventTarget(), textContent: "", href: "", hidden: false,
      classList: {
        add(...names) { names.forEach((name) => classes.add(name)); },
        remove(...names) { names.forEach((name) => classes.delete(name)); },
        contains(name) { return classes.has(name); },
      },
      setAttribute(name, value) { attributes.set(name, value); },
      getAttribute(name) { return attributes.get(name) ?? null; },
      removeAttribute(name) { attributes.delete(name); },
      contains(child) { return child === target || target.children?.includes(child); },
      focus() { document.activeElement = target; },
      getBoundingClientRect() { return target.rect || { left: 0, right: 100, top: 0, bottom: 40 }; },
    };
    elements.set(selector, target);
  }
  return elements.get(selector);
}
const downloadSelectors = ["[data-installer-link]", "[data-windows-link]", "[data-portable-link]", "[data-linux-link]"];
global.document = {
  ...eventTarget(), querySelector: element,
  querySelectorAll() { return downloadSelectors.map(element); },
  body: {}, activeElement: null,
};
let time = 0;
let nextTimer = 0;
const timers = new Map();
global.window = {
  ...eventTarget(),
  setTimeout(callback, delay) { const id = nextTimer++; timers.set(id, { callback, at: time + delay }); return id; },
  clearTimeout(id) { timers.delete(id); },
};
function advance(milliseconds) {
  const end = time + milliseconds;
  while (true) {
    const pending = [...timers].filter(([, timer]) => timer.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
    if (!pending) break;
    time = pending[1].at;
    timers.delete(pending[0]);
    pending[1].callback();
  }
  time = end;
}

(async () => {
  const calculated = buildReleaseData(releases, "2026-08-14T00:00:00Z");
  assert.equal(calculated.featured.tag, "v3.2.0");
  assert.equal(calculated.installer.download_count, 7);
  assert.equal(calculated.totals.installer_downloads, 31, "totals include prereleases and exclude drafts");
  assert.throws(() => buildReleaseData(require("./fixtures/releases-without-installer.json")), /No stable release/);
  assert.throws(() => buildReleaseData({}), /invalid/);

  for (const [navigatorLike, expected] of [
    [{ userAgentData: { platform: "Windows" }, userAgent: "Windows NT 10.0" }, { os: "windows", arch: "x64", available: true }],
    [{ platform: "Linux x86_64", userAgent: "X11; Linux x86_64" }, { os: "linux", arch: "x64", available: true }],
    [{ userAgentData: { platform: "Windows", async getHighEntropyValues() { return { architecture: "arm", bitness: "64" }; } }, userAgent: "Windows NT 10.0" }, { os: "windows", arch: "arm64", available: false }],
    [{ platform: "MacIntel", userAgent: "Macintosh" }, { os: "macos", arch: "x64", available: false }],
    [{ platform: "Linux aarch64", userAgent: "X11; Linux aarch64" }, { os: "linux", arch: "arm64", available: false }],
    [{ platform: "Linux", userAgent: "Android" }, { os: "other", arch: "unknown", available: false }],
  ]) assert.deepEqual(await detectDevice(navigatorLike), expected);

  element("[data-download-stats]").hidden = false;
  setRecommendationText({ os: "linux", arch: "x64", available: true }, calculated);
  assert.equal(element("[data-installer-link]").href, calculated.alternatives.linux_x64.url);
  assert.match(element("[data-platform-heading]").textContent, /Linux/);
  assert.equal(element("[data-download-stats]").hidden, false, "explicitly labelled Windows counts remain visible on Linux");
  setRecommendationText({ os: "macos", arch: "arm64", available: false }, calculated);
  assert.equal(element("[data-installer-link]").href, fallback);
  assert.match(element("[data-platform-heading]").textContent, /macOS/);
  assert.equal(element("[data-download-stats]").hidden, false);

  const originalWarn = console.warn;
  console.warn = () => {};
  try {
    let calls = [];
    global.fetch = async (url) => {
      calls.push(url);
      return { ok: true, json: async () => releases };
    };
    await hydrateRelease();
    assert.equal(calls.length, 1);
    assert.match(element("[data-release-version]").textContent, /v3.2.0/);
    assert.equal(element("[data-installer-downloads]").textContent, "7");
    assert.equal(element("[data-total-downloads]").textContent, "31");
    assert.equal(element("[data-windows-link]").href, calculated.installer.url);

    calls = [];
    global.fetch = async (url) => {
      calls.push(url);
      return { ok: true, json: async () => url.endsWith("page=1") ? Array.from({ length: 100 }, () => ({ draft: true })) : releases };
    };
    await hydrateRelease();
    assert.equal(calls.length, 2, "live release history must be paginated");
    assert.equal(element("[data-total-downloads]").textContent, "31");

    global.fetch = async (url) => {
      if (url.includes("api.github.com")) return { ok: false, status: 403 };
      return { ok: true, json: async () => snapshot };
    };
    await hydrateRelease();
    assert.match(element("[data-release-version]").textContent, new RegExp(snapshot.featured.tag.replaceAll(".", "\\.")));
    assert.match(element("[data-release-status]").textContent, /發布快照/);
    assert.equal(element("[data-download-stats]").hidden, false);

    global.fetch = async () => { throw new Error("fixture network failure"); };
    await hydrateRelease();
    assert.equal(element("[data-installer-link]").href, fallback);
    assert.equal(element("[data-download-stats]").hidden, true);
    assert.equal(element("[data-download-label]").textContent, "查看 GitHub Releases");
    assert.match(element("[data-release-status]").textContent, /無法讀取版本資料/);
  } finally { console.warn = originalWarn; }

  const originalNow = Date.now;
  Date.now = () => time;
  try {
    const prompt = element("[data-star-prompt]");
    const close = element("[data-star-prompt-close]");
    prompt.children = [close];
    prompt.hidden = true;
    prompt.rect = { left: 500, right: 800, top: 500, bottom: 800 };
    const primary = element("[data-installer-link]");
    const portable = element("[data-portable-link]");
    const linux = element("[data-linux-link]");
    const windows = element("[data-windows-link]");
    let cleanup = setupStarPrompt();

    primary.href = fallback;
    primary.emit("click");
    advance(5000);
    assert.equal(prompt.hidden, true, "Releases fallback must not trigger a prompt");
    portable.href = calculated.alternatives.windows_portable.url;
    portable.setAttribute("aria-disabled", "true");
    portable.emit("click");
    advance(5000);
    assert.equal(prompt.hidden, true, "unavailable assets must not trigger a prompt");
    portable.removeAttribute("aria-disabled");

    primary.href = calculated.installer.url;
    primary.focus();
    primary.emit("click");
    advance(4499);
    assert.equal(prompt.hidden, true);
    advance(1);
    assert.equal(prompt.hidden, false);
    assert.equal(document.activeElement, primary, "revealing never steals focus");
    advance(12000);
    assert.equal(prompt.hidden, true, "prompt auto-dismisses after 12 seconds");

    primary.emit("click");
    advance(3000);
    primary.emit("click");
    advance(1500);
    assert.equal(prompt.hidden, true, "repeat click resets the pending reveal");
    advance(3000);
    assert.equal(prompt.hidden, false);
    close.focus();
    close.emit("click");
    assert.equal(prompt.hidden, true);
    assert.equal(document.activeElement, primary, "closing a focused prompt returns focus to its download link");

    for (const [link, url] of [[portable, calculated.alternatives.windows_portable.url], [linux, calculated.alternatives.linux_x64.url], [windows, calculated.installer.url]]) {
      link.href = url;
      link.focus();
      link.emit("click");
      advance(4500);
      assert.equal(prompt.hidden, false, "every actual asset click shows the prompt again");
      document.emit("keydown", { key: "Escape" });
      assert.equal(prompt.hidden, true);
    }

    primary.emit("click");
    advance(4500);
    advance(3000);
    prompt.emit("mouseenter");
    advance(20000);
    assert.equal(prompt.hidden, false, "hover pauses auto-dismiss");
    prompt.emit("focusin");
    prompt.emit("mouseleave");
    advance(20000);
    assert.equal(prompt.hidden, false, "focus pauses auto-dismiss independently from hover");
    prompt.emit("focusout", { relatedTarget: primary });
    advance(8999);
    assert.equal(prompt.hidden, false);
    advance(1);
    assert.equal(prompt.hidden, true, "leaving resumes the remaining time");

    primary.emit("click");
    advance(4500);
    primary.emit("click");
    advance(4500);
    assert.equal(prompt.hidden, false, "another download replaces a currently visible prompt");
    advance(11999);
    assert.equal(prompt.hidden, false, "a replacement owns its full display duration");
    advance(1);
    assert.equal(prompt.hidden, true);

    primary.rect = { left: 600, right: 700, top: 550, bottom: 600 };
    primary.focus();
    primary.emit("click");
    advance(4500);
    assert.equal(prompt.classList.contains("is-inline"), true, "prompt must not cover keyboard focus");
    cleanup();
    assert.equal(timers.size, 0);
    cleanup = setupStarPrompt();
    primary.emit("click");
    advance(4500);
    assert.equal(prompt.hidden, false, "fresh page initialization still shows the prompt");
    cleanup();
  } finally { Date.now = originalNow; }
  console.log("Release selection, device recommendation, live/snapshot fallback and repeatable Star prompt tests passed.");
})().catch((error) => { console.error(error); process.exitCode = 1; });
