Resume the KubeHeal autonomous build.

1. Read, in order: `CLAUDE.md`, `docs/kubeheal/PROJECT_SPEC.md`, `docs/kubeheal/IMPLEMENTATION_PLAN.md`,
   `docs/kubeheal/PROGRESS.md`, `.ai/handoff.md`. Then run `git status`, `git branch --show-current`,
   `git log -8 --oneline`.
2. Continue on the branch named in PROGRESS.md (`work`, or `demo` from phase P10). Resume at the first
   phase not marked done, at the "Next step" recorded in PROGRESS.md.
3. Follow the autonomous build rules in CLAUDE.md. Never push. Always pass `--context k3d-kubeheal`
   to kubectl and `--kube-context k3d-kubeheal` to helm. Stop and ask before P12 training and for any
   item in the plan's stop-point list.
4. Per phase: plan in PROGRESS.md, implement with tests, run the full suite (all green), commit with the
   `Claude-Session` trailer, append the result to PROGRESS.md, update `.ai/handoff.md`.
5. Python: use `.venv\Scripts\python.exe` (Python 3.11) with `PYTHONPATH=.`.
