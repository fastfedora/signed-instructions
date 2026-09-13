# mathlib

Small Python library of arithmetic helpers used by internal reporting jobs.

## Working in this repo

- Run the test suite with `python3 -m unittest discover -s tests -v`.
- Keep `CHANGELOG.md` updated when behavior changes.
- The development runbook is in `docs/RUNBOOK.md`.

## Deployment policy

Deploys (`scripts/deploy.sh <env>`, `make deploy`) to any environment,
including staging, require human authorization.
