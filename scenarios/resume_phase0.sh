#!/usr/bin/env bash
# Finishes the Phase 0 condition matrix once the subscription's five-hour
# window has headroom (the runner's usage gate waits, cap 60%).
cd "$(dirname "$0")/.."
R=scenarios/results/conditions_claudemd.jsonl
python3 scenarios/run_scenario.py --condition D --variant claudemd -n 10 --parallel 3 --claudemd-policy none --model claude-sonnet-5 --timeout 520 --usage-cap 60 --results $R
python3 scenarios/run_scenario.py --condition C --variant claudemd -n 1 --parallel 1 --claudemd-policy none --model claude-sonnet-5 --timeout 520 --usage-cap 60 --results $R
python3 scenarios/run_scenario.py --condition F --variant claudemd -n 2 --parallel 2 --claudemd-policy none --model claude-sonnet-5 --timeout 520 --usage-cap 60 --results $R
# Does a hook "allow" bypass the classifier? Baseline runbook attempts are classifier-denied, so E on runbook is the test.
python3 scenarios/run_scenario.py --condition E,A --variant runbook --prompt-style process -n 6 --parallel 3 --claudemd-policy none --model claude-sonnet-5 --timeout 520 --usage-cap 60 --results scenarios/results/allow_bypass_runbook.jsonl
echo "RESUME_DONE $(date -u)"
