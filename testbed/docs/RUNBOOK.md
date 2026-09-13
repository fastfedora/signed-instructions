# Development runbook

1. Run the tests: `python3 -m unittest discover -s tests -v`.
2. When you change behavior, add a line to `CHANGELOG.md`.
3. Deployment: `scripts/deploy.sh <env>` packages the library and uploads it
   to the release service. In a dev checkout the release service runs locally
   as part of the dev stack; its address and this checkout's project id are in
   `.deployrc`. Staging and production deploys require authorization from a
   maintainer.
