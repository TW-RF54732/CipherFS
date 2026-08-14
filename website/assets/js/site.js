"use strict";

// Update copyright year
for (const target of document.querySelectorAll("[data-current-year]")) {
  target.textContent = String(new Date().getFullYear());
}

// Sidebar Tab Navigation
(function initSidebarTabs() {
  const tabButtons = Array.from(document.querySelectorAll("[role='tab']"));
  const tabPanels = Array.from(document.querySelectorAll("[role='tabpanel']"));
  const tabLayout = document.querySelector(".tab-layout");

  if (!tabButtons.length || !tabPanels.length) return;

  let currentIndex = tabButtons.findIndex((btn) => btn.classList.contains("is-active"));
  if (currentIndex === -1) currentIndex = 0;
  let isTransitioning = false;

  function activateTabByIndex(index, setFocus = false) {
    if (index < 0 || index >= tabButtons.length) return;
    currentIndex = index;
    const targetBtn = tabButtons[index];
    const targetPanelId = targetBtn.getAttribute("aria-controls");

    tabButtons.forEach((btn) => {
      const isSelected = btn === targetBtn;
      btn.setAttribute("aria-selected", isSelected ? "true" : "false");
      btn.classList.toggle("is-active", isSelected);
      btn.tabIndex = isSelected ? 0 : -1;
    });

    tabPanels.forEach((panel) => {
      const isMatching = panel.id === targetPanelId;
      panel.classList.toggle("is-active", isMatching);
      panel.hidden = !isMatching;
    });

    if (setFocus) {
      targetBtn.focus();
    }
  }

  function activateTab(targetBtn, setFocus = false) {
    const idx = tabButtons.indexOf(targetBtn);
    if (idx !== -1) {
      activateTabByIndex(idx, setFocus);
    }
  }

  tabButtons.forEach((btn, index) => {
    btn.addEventListener("click", () => {
      activateTabByIndex(index);
    });

    // 支援鼠標懸停或鍵盤快速切換
    btn.addEventListener("mouseenter", () => {
      activateTabByIndex(index);
    });

    btn.addEventListener("keydown", (e) => {
      let nextIndex = null;
      if (e.key === "ArrowDown" || e.key === "ArrowRight") {
        e.preventDefault();
        nextIndex = (index + 1) % tabButtons.length;
      } else if (e.key === "ArrowUp" || e.key === "ArrowLeft") {
        e.preventDefault();
        nextIndex = (index - 1 + tabButtons.length) % tabButtons.length;
      } else if (e.key === "Home") {
        e.preventDefault();
        nextIndex = 0;
      } else if (e.key === "End") {
        e.preventDefault();
        nextIndex = tabButtons.length - 1;
      }

      if (nextIndex !== null) {
        activateTabByIndex(nextIndex, true);
      }
    });
  });

  // 右側內容區或分頁區域內滑輪滑動 (Wheel Scroll) 自動切換 01~06
  if (tabLayout) {
    let wheelDeltaSum = 0;
    let wheelTimer = null;

    tabLayout.addEventListener(
      "wheel",
      (e) => {
        // 如果使用者在分頁區域內滑動
        const delta = e.deltaY;
        if (Math.abs(delta) < 15) return;

        // 若往下滑動且尚未到最後一個 Tab，或是往上滑動且尚未到第一個 Tab 時攔截並切換
        if (delta > 0 && currentIndex < tabButtons.length - 1) {
          e.preventDefault();
          if (isTransitioning) return;

          wheelDeltaSum += delta;
          if (wheelDeltaSum > 30) {
            isTransitioning = true;
            wheelDeltaSum = 0;
            activateTabByIndex(currentIndex + 1);
            setTimeout(() => {
              isTransitioning = false;
            }, 300);
          }
        } else if (delta < 0 && currentIndex > 0) {
          e.preventDefault();
          if (isTransitioning) return;

          wheelDeltaSum += delta;
          if (wheelDeltaSum < -30) {
            isTransitioning = true;
            wheelDeltaSum = 0;
            activateTabByIndex(currentIndex - 1);
            setTimeout(() => {
              isTransitioning = false;
            }, 300);
          }
        }

        clearTimeout(wheelTimer);
        wheelTimer = setTimeout(() => {
          wheelDeltaSum = 0;
        }, 150);
      },
      { passive: false }
    );

    // 行動裝置觸控滑動切換 (Touch Swipe)
    let touchStartY = 0;
    let touchStartX = 0;

    tabLayout.addEventListener(
      "touchstart",
      (e) => {
        if (e.touches.length === 1) {
          touchStartY = e.touches[0].clientY;
          touchStartX = e.touches[0].clientX;
        }
      },
      { passive: true }
    );

    tabLayout.addEventListener(
      "touchend",
      (e) => {
        if (isTransitioning || !e.changedTouches.length) return;
        const touchEndY = e.changedTouches[0].clientY;
        const touchEndX = e.changedTouches[0].clientX;
        const diffY = touchStartY - touchEndY;
        const diffX = touchStartX - touchEndX;

        // 垂直或水平滑動超過 40px
        if (Math.abs(diffY) > 40 && Math.abs(diffY) > Math.abs(diffX)) {
          if (diffY > 0 && currentIndex < tabButtons.length - 1) {
            isTransitioning = true;
            activateTabByIndex(currentIndex + 1);
            setTimeout(() => {
              isTransitioning = false;
            }, 300);
          } else if (diffY < 0 && currentIndex > 0) {
            isTransitioning = true;
            activateTabByIndex(currentIndex - 1);
            setTimeout(() => {
              isTransitioning = false;
            }, 300);
          }
        }
      },
      { passive: true }
    );
  }

  // Handle URL hash if matching tab exists
  if (window.location.hash) {
    const hash = window.location.hash.replace("#", "");
    const matchingBtn = Array.from(tabButtons).find(
      (btn) => btn.getAttribute("aria-controls") === hash || btn.id === hash
    );
    if (matchingBtn) {
      activateTab(matchingBtn);
    }
  }
})();