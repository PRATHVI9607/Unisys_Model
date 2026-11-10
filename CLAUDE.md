@AGENTS.md

## Claude Code specifics

- Deny rules exist in `.claude/settings.json` (git push and destructive git commands, `k3d cluster delete`).
  They were not proven enforced in-session; the git-level guard in `AGENTS.md` ("Push guard") is the real block.
- Subagents live in `.claude/agents/`: `kubeheal-reviewer` (read-only phase review) and `kubeheal-builder`
  (implements one phase in its own git worktree and branch).
- Orchestrator mode: the main session assigns phases to builders (at most 2 at once unless the owner says
  otherwise), runs the reviewer after each phase, fixes findings, merges in the order set in
  `docs/kubeheal/IMPLEMENTATION_PLAN.md`, and owns the k3d cluster.
