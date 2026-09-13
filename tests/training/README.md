# Blind-CVE training (local commands)

Canonical contract: [`docs/TRAINING.md`](../../docs/TRAINING.md).

```bash
.venv/bin/python tests/training/weekly.py --preflight-only
.venv/bin/python tests/training/weekly.py --rescan
.venv/bin/python tests/training/weekly.py --grow
.venv/bin/python tests/training/nim_suggest.py --dry-run
.venv/bin/python tests/training/nim_suggest.py --limit 5
.venv/bin/python -m pytest -q
```
