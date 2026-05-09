# Static dashboard mockups

Two single-file HTML pages used as design references for the IDProva agent dashboard. They are *mockups* — no build step, no backend. Both files load `tweetnacl@1.0.3` from a CDN to do real Ed25519 operations in-browser, but state is held in `localStorage` only.

These files exist so designers, contributors, and prospective users can open the agent UX in any browser without touching the React demo (`web/`) or the production portal (`idprova-portal/`).

## Files

- `app.html` — full agent management mockup. Sidebar navigation across "My Agents", "Security Demos", and "Test Suite" sections. Demonstrates the proposed agent listing, scope grants, and a built-in test runner UI.
- `index.html` — narrower control-panel view used as a landing page / pitch surface. Hero copy ("Your AI agents need verified identities") plus condensed primitives.

If you're looking for a runnable React app, use [`../web/`](../web/). If you're looking for the production customer portal, see [`idprova-portal`](https://github.com/techblaze-au/idprova-portal).

## How to view

Open the file directly in a browser:

```bash
# from repo root
open dashboard/app.html        # macOS
xdg-open dashboard/app.html    # Linux
start dashboard/app.html       # Windows PowerShell
```

There is no `npm install` and no server. The `tweetnacl` script tag fetches from the jsDelivr CDN at page load.

## Notes

- These pages are mockups, not the canonical UI. Treat them as design artifacts; production routes and component contracts live in `idprova-portal`.
- Persistent state is `localStorage`-only. Clearing site data resets everything.
- No tests apply to this directory.
