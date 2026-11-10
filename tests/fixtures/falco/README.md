# Falco replay fixtures

These files are HAND-WRITTEN. They were not captured from a running Falco. They follow the Falco JSON
output format (one JSON object per line: `hostname`, `output`, `output_fields`, `priority`, `rule`,
`source`, `tags`, `time`) so the replay path exercises the same parser as live Falco. Pod name, container
id, PIDs and timestamps are invented for the test; the rule names and the `fd.name` / `k8s.*` / `proc.pid`
field names match `k8s/falco-kubeheal-rules.yaml`. Lines starting with `#` are comments for readers; the
replay reader skips them.

| File | Content |
|---|---|
| `ransomware_pv_encrypt.jsonl` | 12 files: write then rename to `.locked`, then a ransom note, pid 4242 on `/data`. Rule outputs carry `evt.type` (what the rules should emit). |
| `ransomware_pv_encrypt_current_rules.jsonl` | The same attack with 10 files and no `evt.type`, which is what the rules in `k8s/` produce today (their output strings do not reference `evt.type`). |
| `benign_sensitive_read.jsonl` | A trusted process reading `/etc` files; no KubeHeal rule matches. |

When Falco runs on a machine, record real traces into this directory (`file_output` with `json_output: true`)
and keep the hand-written ones next to them, clearly separated by name.

Use: `FALCO_MODE=replay FALCO_REPLAY_PATH=tests/fixtures/falco/ransomware_pv_encrypt.jsonl`.
