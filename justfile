# Signed Instruction Blocks: common tasks. Run `just` to list them.

default:
  @just --list

# Run the test suite
[group: 'Testing']
test:
  .venv/bin/python -m pytest -q

# Run the no-model terminal demo
[group: 'Testing']
demo:
  ./demo.sh

# Preview the documentation with live reload
[group: 'Documentation']
docs:
  just docs-build-api
  PATH="$PWD/.venv/bin:$PATH" quarto preview docs --port 4200

# Build the API reference pages
[group: 'Documentation']
docs-build-api:
  .venv/bin/python scripts/gen_quarto_api.py

# Build the full documentation, including the API reference pages
[group: 'Documentation']
docs-build:
  just docs-build-api
  PATH="$PWD/.venv/bin:$PATH" quarto render docs

# View the documentation locally
[group: 'Documentation']
view-docs:
  PATH="$PWD/.venv/bin:$PATH" quarto preview docs --port 4200
