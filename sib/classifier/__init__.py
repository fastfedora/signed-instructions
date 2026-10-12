"""The reference permission-classifier policy (CI-1).

SIB does not ship a classifier. It verifies signatures and hands the
harness's own classifier a provenance manifest. `policy.md` is the text an
integrator gives that classifier so it knows how to weigh the manifest.
"""
from pathlib import Path

POLICY_PATH = Path(__file__).with_name("policy.md")


def load_policy_text() -> str:
    """The reference policy, for an integrator to paste into their classifier."""
    return POLICY_PATH.read_text()
