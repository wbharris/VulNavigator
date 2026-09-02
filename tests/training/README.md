# Blind-CVE training (local commands)

Canonical contract: [`docs/TRAINING.md`](../../docs/TRAINING.md).

```bash
.venv/bin/python tests/training/weekly.py --preflight-only
.venv/bin/python tests/training/weekly.py --rescan
.venv/bin/python tests/training/weekly.py --grow
.venv/bin/python -m pytest -q
```
