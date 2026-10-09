# CipherFS Website Design System

## Direction

A Traditional Chinese product website for Windows users, following quiet-web-design.
Present real workflows with real screenshots. Keep the Hero static, the page naturally
scrollable, and technical details subordinate to the next useful action.

## Tokens

- Canvas: `#141414`; surface: `#202020`; secondary surface: `#1b1b1b`.
- Primary text: `#f5f5f5`; body: `#c0c0c0`; secondary: `#b5b5b5`.
- Dividers: `#343434`; control borders: `#484848`.
- Primary action: `#eeeeee` with `#141414` text.
- System sans-serif with Chinese fallbacks; monospace only for code and paths.
- Hero: responsive 36–72px; headings: 26–34px; body: 16–17px.
- Content width: 1240px maximum; desktop gutters: 4vw; mobile gutters: 20px.
- Section spacing: 48–80px; buttons: at least 48px high, 7px radius.
- Screenshots and bounded panels: 12px radius, thin border, no decorative shadow.

The original App icon and screenshots retain their colors. Website controls use gray
rather than borrowing the application's blue. No decorative Hero animation is included.

## Page hierarchy

- Homepage: product benefit and download → pack → container operations → read-only
  browsing → local/open-source principles → compact experimental boundary → download.
- Download: recommendation, release metadata, Installer counts → installation
  expectations → first Explorer action → alternative assets and verification → boundary.
- 404: clear message, home and download actions, shared navigation and footer.

Desktop workflows alternate image/text placement. On mobile, the explanation always
precedes its screenshot. Content remains visible without JavaScript.

## Download behavior

Preserve the release JSON contract, device recommendation, live API/snapshot/Releases
fallback, and Installer-only counts (not unique users). Counts remain visible across
platforms with an explicit Windows Installer label. Unavailable counts are hidden.

Every real Installer, portable ZIP, or Linux archive click schedules the Star prompt
4.5 seconds later. Repeated clicks reset that timer without creating another prompt.
No persistent storage or frequency limit. Releases and verification links do not trigger it.
The prompt never claims that a download succeeded and opens GitHub in a separate tab.

The prompt is non-modal, does not take focus, and supports close and Escape. It auto-hides
after 12 seconds, pausing while hovered or keyboard-focused. If focus would be covered,
it uses its inline position instead. At widths of 900px or less it is inline below the
release panel, so mobile download controls remain accessible.

## Accessibility and checks

Use semantic landmarks, one h1 per page, descriptive image alt text, declared image
sizes, a skip link, current-page navigation, and a visible 2px focus outline. Text meets
WCAG AA contrast. Links and controls have at least 44px touch targets. Hover never
reveals required content. Reduced-motion disables transitions.

Check 375, 768, 1024 and 1440px layouts, native scroll, keyboard navigation, and all
release states. Run Node download tests, JavaScript syntax checks, release fixture tests
and site validation before deployment through the existing GitHub Pages workflow.
