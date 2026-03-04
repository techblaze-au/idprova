# IDProva — How to Start Any Session

> Read this FIRST when opening a new Claude Code session for IDProva work.

## Step 1: Check Master Board
```bash
cat IDPROVA-MASTER.md
```
Find which tracks are READY TO START and which are BLOCKED.

## Step 2: Check for Handovers
```bash
ls HANDOVERS/ 2>/dev/null && cat HANDOVERS/<latest-file-for-your-track>
```

## Step 3: Set Up Worktrees (first time only)
```bash
# Run once to set up all tracks
mkdir -p .agent-signals/{locks,completions,handoffs,messages}
mkdir -p HANDOVERS

git worktree add worktrees/track-a -b idprova/track-a-core-security  2>/dev/null || git worktree add worktrees/track-a idprova/track-a-core-security
git worktree add worktrees/track-b -b idprova/track-b-registry  2>/dev/null || git worktree add worktrees/track-b idprova/track-b-registry
git worktree add worktrees/track-c -b idprova/track-c-sdk-cli  2>/dev/null || git worktree add worktrees/track-c idprova/track-c-sdk-cli
git worktree add worktrees/track-d -b idprova/track-d-docs-website  2>/dev/null || git worktree add worktrees/track-d idprova/track-d-docs-website
```

## Step 4: Work in Your Track's Worktree
```bash
cd worktrees/track-{x}    # e.g. track-a
cargo test --workspace    # confirm green before starting
```

## Step 5: When Context is ~65% Full — Write Handover
```bash
# Create handover doc
cat > ../../HANDOVERS/P{N}-S{M}-track-{x}.md << 'EOF'
# Handover: Phase N, Session M, Track X
**Date:** YYYY-MM-DD
**Branch:** idprova/track-x

## ✅ Completed This Session
-

## 🔄 In Progress (pick up here)
-

## ❌ Not Started (remaining this phase)
-

## 🧪 Test Status
- cargo test --workspace: PASSING / FAILING
- New tests added: N

## 🔑 Key Decisions Made
-

## 📋 Next Session Instructions
1. Read this file
2. Run: cargo test --workspace
3. Continue from: [specific file, function, line]

## 📁 Files Modified
| File | Changes |
|------|---------|
EOF

# Commit and signal
git add ../../HANDOVERS/
git commit -m "handover: Phase N Session M - [brief description]"
git push origin idprova/track-x
touch ../../.agent-signals/handoffs/P{N}-S{M}-track-{x}.done
```

## Step 6: When Phase is COMPLETE — Merge to Main
```bash
cd ../..  # back to repo root
git checkout main
git merge idprova/track-{x} --no-ff -m "feat: Phase N complete - [description]"
git push origin main

# Update IDPROVA-MASTER.md (tick off the gate)
# Signal completion
touch .agent-signals/completions/P{N}-track-{x}.done
```

---

## Quick Reference: What Tracks to Start RIGHT NOW

| Track | Worktree | First Session Tasks |
|-------|----------|-------------------|
| **A** (READY) | `worktrees/track-a` | Phase 0, Session A-1: Fix JWS re-serialization + receipt sigs |
| **D** (READY) | `worktrees/track-d` | Session D-1: git init both repos + fix idprova.astro + Windows deps |

Tracks B, C, E, F are BLOCKED — see IDPROVA-MASTER.md for unlock gates.

---

## Full Plan Reference
- **Plan file:** `C:\Users\praty\.claude\plans\rustling-roaming-peach.md`
- **Notion Architecture Plan:** https://www.notion.so/3184683942b081bc9f95f638e0312fac
- **Notion Gap Analysis:** https://www.notion.so/3184683942b081f68f2ff26f87c88d3a