# Pre-Launch Checklist

> Tick these off before launch week (Mar 24). Do them in order.

---

## Evening 1: Publish Everything (Mar 14-16)

### Gate 1: "Can someone install it?"

- [x] Quick-start doc audit — verify API names match current code ✅ (Mar 14 — fixed TS: Aid→AID, AidBuilder→AIDBuilder; Python: missing AID import, undocumented params)
- [ ] Make GitHub repo **PUBLIC** (Settings > Danger Zone > Change visibility)
- [ ] Create git tag: `git tag -a v0.1.0 -m "IDProva v0.1.0 — initial release"`
- [ ] Push tag: `git push origin v0.1.0` (triggers release workflow)
- [ ] Wait for GitHub Actions to complete (builds binaries + Docker image)
- [x] Publish to crates.io ✅ (Mar 14 — all 5 crates live, 0.1.0)
  1. ~~`cd crates/idprova-core && cargo publish`~~ ✅
  2. ~~`cd crates/idprova-verify && cargo publish`~~ ✅
  3. ~~`cd crates/idprova-middleware && cargo publish`~~ ✅
  4. ~~`cd crates/idprova-registry && cargo publish`~~ ✅
  5. ~~`cd crates/idprova-cli && cargo publish`~~ ✅
- [ ] Publish Python SDK: `cd sdks/python && maturin publish` (wheel built, publish deferred to launch)
- [ ] Publish TypeScript SDK: `cd sdks/typescript/packages/core && npm publish` (deferred)
- [ ] **VERIFY:** `cargo install idprova-cli` → `idprova --help` works
- [ ] **VERIFY:** `pip install idprova` → `python -c "import idprova"` works
- [ ] **VERIFY:** `docker pull ghcr.io/techblaze-au/idprova-registry` works

---

## Evening 2: Website Verification (Mar 17-18)

### Gate 2: "Does the website work?"

- [ ] Visit `https://idprova.dev` — loads correctly
- [ ] Click every sidebar link (35 pages) — no broken links
- [x] Read Quick Start page — code examples match published package names ✅ (Mar 14 — replaced placeholder with full multi-language guide)
- [x] Update install instructions — all "April 7" dates updated to "March 2026" across 15 files ✅
- [ ] Test early access form submission → check Google Sheet receives entry
- [ ] Verify all 6 blog posts render correctly
- [ ] Check OG meta tags work (paste URL in Twitter/LinkedIn preview)
- [ ] Mobile responsive check (shrink browser window)

---

## Evening 3: Draft Launch Content (Mar 19-21)

### Gate 3: "Can I announce it?"

- [x] Draft Hacker News "Show HN" post ✅ (Mar 14 — in `10-LAUNCH-CONTENT-DRAFTS.md`)
- [x] Draft X/Twitter launch thread (7 tweets) ✅
- [x] Draft LinkedIn announcement post ✅
- [x] Draft Reddit post for r/rust ✅
- [x] Draft Reddit post for r/netsec ✅
- [x] Draft Reddit post for r/MachineLearning ✅
- [x] Prepare Dev.to cross-post of "The AI Agent Identity Crisis" ✅
- [x] Save all drafts in `LAUNCH/10-LAUNCH-CONTENT-DRAFTS.md` ✅

---

## Final Check (Mar 23, night before)

- [ ] All 3 gates above are green
- [ ] GitHub release page has binaries for Linux/macOS/Windows
- [ ] Docker image is pullable from GHCR
- [ ] idprova.dev has no broken links
- [ ] All launch posts are drafted and reviewed
- [ ] Clear your calendar for Mar 24 (HN launch day — need 4+ hours online)
