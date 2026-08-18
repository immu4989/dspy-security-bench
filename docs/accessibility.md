# Accessibility statement and test checklist

The project aims for WCAG 2.2 AA and Section 508-compatible documentation and
dashboard interactions, but does not claim formal conformance.

The static dashboard provides semantic landmarks, a skip link, keyboard-usable
filters and copy controls, labeled search, focusable chart points, text-backed
tables, live status for tooltips, responsive layouts, and reduced-motion
behavior. Color is not intended to be the only carrier of result state.

Before each visual release, check:

- keyboard traversal, visible focus, menu open/close state, and no keyboard trap;
- 200% and 400% zoom without loss of content or function;
- screen-reader names, headings, landmarks, table headers, and dynamic status;
- text and non-text contrast in every result state;
- reduced motion and high-contrast/forced-color behavior;
- mobile reflow at 320 CSS pixels;
- copy actions when Clipboard API permission is unavailable; and
- the experience with scripts or external font delivery unavailable.

Please report barriers through GitHub Issues without including personal or
sensitive information. Accessibility in the benchmark UI does not establish
accessibility of any evaluated AI system; agencies and companies must test the
actual user journey, content, assistive technologies, and accommodation process.
