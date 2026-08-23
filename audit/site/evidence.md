# Evidence — the site itself (thekinghippopotamus.github.io)

Claims made about this site, with the command that verifies each. Re-run by an independent checker before publish.

| Claim | Command | Result |
|---|---|---|
| Zero third-party requests: no fonts, CDN, images, scripts or analytics from other hosts | `grep -rhoE 'https?://[a-zA-Z0-9.-]+' --include=*.html --include=*.xml --include=*.txt . \| sort -u` → `http://www.sitemaps.org https://github.com https://thekinghippopotamus.github.io ` (own origin, GitHub, and the sitemap XML namespace identifier — never fetched) | verified |
| No JavaScript anywhere | `grep -rc '<script' --include=*.html . ` → 0 on every page | verified |
| Built by a stdlib-only Python generator; no Node, no build service | generator `build.py` (455 lines) imports only json, pathlib, html, re, datetime; built HTML is committed as-is | verified |
| Publish gate passed before `git init` (gitleaks + identity-guard + denylist + external-request check + filename denylist) | `publish_gate.py --mode cleanroom --repo .` → PASS 6/6 | verified |
| Case studies can only be published with re-run evidence | `build.py` refuses status=published with zero verified rows or fewer than 3 limitations (tested 2026-08-23: three refusal cases, exit 1) | verified |

Generated 2026-08-23. Pseudonymous by design; see /about/.
