"use strict";

for (const target of document.querySelectorAll("[data-current-year]")) {
  target.textContent = String(new Date().getFullYear());
}
