# CipherFS Website Design System

This document is the source of truth for the two-page CipherFS product website.
It distills the UI UX Pro Max recommendation for a low-variance, low-motion,
Swiss-style product site while preserving the established CipherFS brand.

## Direction

- Pattern: minimal and direct product landing page.
- Mood: precise, quiet, technical, and trustworthy without implying audited security.
- Composition: strong typographic hierarchy, visible grid, generous but purposeful space.
- Brand: black, white, and gray form the structure; GUI blue `#3685f5` is the only accent.
- Avoid: glow, glassmorphism, gradients, decorative blur, neon security motifs, floating cards,
  excessive badges, and animation without functional meaning.

## Tokens

### Color

- Canvas: `#080d13`
- Surface: `#101720`
- Raised surface: `#151d27`
- Primary text: `#f4f7fa`
- Secondary text: `#a9b4c3`
- Quiet text: `#8e9aaa`
- Border: `#2a3542`
- Accent: `#3685f5`
- Accent text on dark surfaces: `#78b1ff`
- Text on accent-filled controls: `#07111f`
- Warning text: `#e6c27a`

Normal text must meet WCAG AA 4.5:1 contrast. Focus indicators must use a visible
2px outline with offset and at least 3:1 state contrast.

### Typography

- Font stack: `Segoe UI Variable`, `Segoe UI`, system sans-serif.
- Code and technical labels: `Cascadia Code`, `Consolas`, monospace.
- Display: responsive 56-112px, 700 weight, compact tracking.
- Section heading: responsive 36-64px, 680 weight.
- Body: 16-19px, 1.65 line height, maximum readable measure of 68 characters.
- Labels: 11-13px, 700 weight, uppercase English where appropriate.

### Layout and spacing

- Maximum content width: 1180px.
- Adaptive gutters: 24px mobile, 32px tablet, 40px desktop.
- Spacing follows an 8px rhythm, with 4px used only for fine alignment.
- Primary breakpoints: 375px, 768px, 1024px, and 1440px.
- Screenshots are full-width within their grid cell and retain declared dimensions to avoid CLS.

## Components

- Navigation: consistent on both pages; active page is indicated by text and underline.
- Buttons: one blue primary action per section; secondary actions use a border only.
- Panels: square-to-moderate 16px radius, 1px border, no decorative shadows or glow.
- Screenshots: one neutral frame treatment, no floating overlap, no artificial perspective.
- Metrics: tabular figures with a clear label; data is hidden when unavailable.
- Download resource rows: full-row links with visible hover, active, focus, and disabled states.
- Star prompt: fixed, compact, dismissible, non-modal, and never obscures keyboard focus.

## Page hierarchy

### Introduction

1. Brand hero: `CipherFS`, Logo, one-sentence definition, download and GitHub actions.
2. Windows Shell promise: Explorer → Pack → `.cfs` operations.
3. Read-only mount: mount window and Explorer disk result.
4. Verifiable product principles.
5. Experimental Duress Password with explicit boundary.
6. Safety boundary and final download action.

### Download

1. Windows Installer as the single primary action.
2. Version, date, size, current asset downloads, and historical installer total.
3. Three installation expectations.
4. First action after installation.
5. Portable/Linux alternatives and verification resources.
6. Experimental software boundary.

## Interaction and accessibility

- All controls remain keyboard reachable and use semantic HTML.
- Minimum mobile control height is 44px; adjacent controls keep at least 8px separation.
- Hover is supplementary; no information or action depends on hover alone.
- Motion is limited to 150-220ms state transitions using opacity or color.
- `prefers-reduced-motion: reduce` disables non-essential transitions.
- Meaningful images have descriptive Traditional Chinese alt text; decorative Logo instances use
  empty alt text where the visible product name already supplies the same information.
- Page content does not horizontally scroll at supported widths.
