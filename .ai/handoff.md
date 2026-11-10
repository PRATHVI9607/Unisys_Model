# Handoff

- **Agent:** Claude Code (orchestrator)
- **Date:** 2026-11-10
- **Branch:** `work`
- **Goal:** Autonomous build of full KubeHeal per `docs/kubeheal/IMPLEMENTATION_PLAN.md` (P0 to P11; P12 needs the user's go).
- **What changed and why:** P0 to P3 are done (details in `docs/kubeheal/PROGRESS.md`). This session made the repo agent-neutral: `AGENTS.md` is the single instruction file (`CLAUDE.md` only imports it), `.githooks/pre-push` blocks pushes unless `ALLOW_PUSH=1` (`core.hooksPath` set; a new clone must run `git config core.hooksPath .githooks`), subagents in `.claude/agents/`, "Task checklist" in PROGRESS.md, wave structure in the plan, `docs/kubeheal/RESUME_ANY_AGENT.md`.
- **Files touched:** AGENTS.md, CLAUDE.md, .githooks/pre-push, .claude/agents/*, docs/kubeheal/{PROGRESS,IMPLEMENTATION_PLAN,RESUME_ANY_AGENT}.md, .ai/handoff.md
- **Open issues:** Named subagents (`kubeheal-builder`, `kubeheal-reviewer`) are not loaded in a running session; general-purpose agents follow the files instead. Claude deny rules in `.claude/settings.json` are not enforced in-session (a `git push --dry-run` to a scratch repo was only stopped by the git hook). Conformal q unused at serve time (P12). k3d cluster `kubeheal` is running; always `--context k3d-kubeheal`.
- **Next step:** Wave 2 batch 1 is running: builders on worktrees `wave/P7` and `wave/P5` (worktrees under the Claude scratchpad `wt/`). When both report: review each with the reviewer, merge in order P7, P5 into `work`, then batch 2 (P4, P9). Review fixes for P0 to P3 are done (6336267); small deferred items are REV-3 in PROGRESS.md. USER RULE: never push.
