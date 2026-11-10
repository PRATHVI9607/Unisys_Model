# Handoff

- **Agent:** Claude Code (orchestrator)
- **Date:** 2026-11-10
- **Branch:** `work`
- **Goal:** Autonomous build of full KubeHeal per `docs/kubeheal/IMPLEMENTATION_PLAN.md` (P0 to P11; P12 needs the user's go).
- **What changed and why:** P0 to P3 are done (details in `docs/kubeheal/PROGRESS.md`). This session made the repo agent-neutral: `AGENTS.md` is the single instruction file (`CLAUDE.md` only imports it), `.githooks/pre-push` blocks pushes unless `ALLOW_PUSH=1` (`core.hooksPath` set; a new clone must run `git config core.hooksPath .githooks`), subagents in `.claude/agents/`, "Task checklist" in PROGRESS.md, wave structure in the plan, `docs/kubeheal/RESUME_ANY_AGENT.md`.
- **Files touched:** AGENTS.md, CLAUDE.md, .githooks/pre-push, .claude/agents/*, docs/kubeheal/{PROGRESS,IMPLEMENTATION_PLAN,RESUME_ANY_AGENT}.md, .ai/handoff.md
- **Open issues:** Claude deny rules in `.claude/settings.json` are not enforced in-session (a `git push --dry-run` to a scratch repo was only stopped by the git hook). Conformal q unused at serve time (P12). k3d cluster `kubeheal` is running; always `--context k3d-kubeheal`.
- **Next step:** run kubeheal-reviewer on P0 to P3 and fix findings, then Wave 2 (P7, P5, P4, P9; at most 2 builders at once), Wave 3 (P6, P8), Wave 4 (P10, P11). USER RULE: never push.
