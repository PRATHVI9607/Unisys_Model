# Resume prompt for any AI tool

Paste this into Claude Code, Codex CLI, OpenCode or any other agent working in this repo.

```
You are continuing the KubeHeal build in this git repository (branch work). Do not ask me to re-explain.

1. Read, in order: AGENTS.md, docs/kubeheal/PROJECT_SPEC.md, docs/dev-notes/IMPLEMENTATION_PLAN.md,
   docs/dev-notes/PROGRESS.md (section "Task checklist"), .ai/handoff.md.
2. Run: git status, git log --oneline -15, git branch. Confirm the branch and
   whether the tree is clean. If there is a wip/<task-id> branch, continue it.
3. Claim the next unchecked task whose dependencies are done by changing its line to "[~] <your agent name>".
   If you are a small local model, take only tasks marked "size: S" and never edit decision_policy.py,
   agents/executor/ or k8s/rbac/.
4. Work in small commits, run the full test suite (PYTHONPATH=. .venv\Scripts\python.exe -m pytest tests/ -q),
   and keep all tests green.
5. Never push, never set ALLOW_PUSH, never run destructive git commands, never touch Kubernetes contexts other
   than k3d-kubeheal, never invent numbers, no em dashes in docs.
6. Before you stop, or when usage or context runs low: commit (or commit to wip/<task-id> with a WIP message),
   mark the task [x] or write exactly where it stopped, and rewrite .ai/handoff.md (agent, date, branch,
   last commit, what is next, open issues).
```
