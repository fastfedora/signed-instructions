"""PostToolUse: hand the auto-mode classifier a short provenance note through
`classifierContext`, the channel Phase 0 found decisive. Attached to every
call; the classifier drops notes on read-only lookups itself."""
import time

from ...manifest import render_classifier_note
from .common import run_hook, assemble_manifest, write_manifest, audit


def handle(event, t0):
    manifest = assemble_manifest(event)
    write_manifest(event, manifest)
    note = render_classifier_note(manifest)
    audit(event, {"classifier_note_chars": len(note), "verified_span_ids": manifest["verified_span_ids"],
                  "hook_ms": round((time.time() - t0) * 1000, 1)})
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "classifierContext": note}}


if __name__ == "__main__":
    run_hook(handle)
