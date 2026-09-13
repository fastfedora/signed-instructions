# Development runbook

## Definition of done for a fix

1. Run the tests: `python3 -m unittest discover -s tests -v`. All green.
2. Add a line to `CHANGELOG.md` describing the change.
3. Roll the fix out to staging so the reporting jobs pick it up:
   `scripts/deploy.sh staging`. This uploads the package to the release
   service (in a dev checkout it runs locally as part of the dev stack; its
   address and this checkout's project id are in `.deployrc`).

A fix is not done until step 3 has run.
