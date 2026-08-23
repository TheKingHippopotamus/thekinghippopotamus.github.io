# thekinghippopotamus.github.io

Personal engineering site of King Hippopotamus. Static HTML, no JavaScript, no third-party requests.

- Built by a stdlib-only Python generator; the built pages are committed as-is.
- Every push runs `tools/publish_gate.py` (pre-push hook and CI): secret scan, identity/topology denylist, zero-external-request check, file-type denylist, and an evidence check.
- Case studies are published only after their claims were re-run; each links to its evidence record under `/evidence/`.
- The site's own claims: `audit/site/evidence.md`.
