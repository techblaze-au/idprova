# Plan: IDProva User Workflow Application (`dashboard/app.html`)

## Status: IN PROGRESS
## Branch: feat/rename-did-method-aid

## Context

The existing `dashboard/index.html` is a **developer control panel** — raw API calls, JWS tokens, scope strings.
`dashboard/app.html` is the **product-quality user interface** for team leads, product managers, developers evaluating IDProva.

## Deliverable

`dashboard/app.html` — ~2200 lines, vanilla JS, no build step, standalone.

## 5-Pass Build Strategy

| Pass | Content | Status |
|------|---------|--------|
| 0 | Save plan + init HANDOVER | DONE |
| 1 | HTML shell + CSS (~400 lines) | TODO |
| 2 | JS Part A: State + Crypto + API helpers + Init | TODO |
| 3 | JS Part B: Overview + Agents + Wizard + Drawer + Grant Access | TODO |
| 4 | JS Part C: Activity Feed + Security Demos A-D | TODO |
| 5 | JS Part D: Test Suite (27 tests, 5 groups) + close tags | TODO |

## Screens

1. **Overview** — hero (no agents) or stats+quick-actions (with agents)
2. **My Agents** — agent grid, Create Agent wizard, Manage Access drawer
3. **Activity** — live feed polling /receipts every 2s
4. **Security** — 4 demo cards (A: happy path, B: impersonation, C: scope, D: revocation)
5. **Test Suite** — 27 tests in 5 groups with run-all

## State Shape

```js
let appState = {
  registryUrl: 'http://localhost:4242',
  mcpUrl: 'http://localhost:3001',
  session: null,
  activeView: 'overview',
  agents: [],
  openDrawer: null,
  liveTokens: {},
};
```

## Key Anchors for Edit Passes

- Pass 2 replaces: `// JS PART A — state, crypto, API`
- Pass 3 appends at: `// JS PART B — overview, agents, wizard`
- Pass 4 appends at: `// JS PART C — activity, demos`
- Pass 5 appends at: `// JS PART D — test suite`

## Test Groups (27 tests)

- Group 1: Auth (7 tests)
- Group 2: Scope Enforcement (5 tests)
- Group 3: Revocation (5 tests)
- Group 4: Malformed Tokens (5 tests)
- Group 5: Registry Edge Cases (5 tests)
