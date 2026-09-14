#!/usr/bin/env python3
"""Pre-render: publish the working files the team needs alongside the guide.

1. Copies plans/**/*.md into docs/project/plans/ (gitignored), adding Quarto
   front matter from each file's first heading and rewriting links that point
   outside the plans folder to the GitHub repository.
2. Generates docs/project/results.qmd from scenarios/results/*.jsonl using the
   scenario runner's own summarizer, so the results page never goes stale.
"""
import json
import re
import shutil
import sys
from pathlib import Path

DOCS = Path(__file__).resolve().parents[1]
ROOT = DOCS.parent
PLANS_SRC = ROOT / "plans"
PLANS_DST = DOCS / "project" / "plans"
RESULTS_SRC = ROOT / "scenarios" / "results"
RESULTS_DST = DOCS / "project" / "results.qmd"
REPO_BLOB = "https://github.com/fastfedora/signed-instructions/blob/main/"

sys.path.insert(0, str(ROOT / "scenarios"))
sys.path.insert(0, str(ROOT / "hooks" / "probe"))


# ---------- plans ----------

def copy_plans() -> None:
    if PLANS_DST.exists():
        shutil.rmtree(PLANS_DST)
    for src in sorted(PLANS_SRC.rglob("*.md")):
        rel = src.relative_to(PLANS_SRC)
        dst = PLANS_DST / (Path("index.md") if rel.name == "README.md" else rel)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(convert_plan(src.read_text(), rel))


ITEM = re.compile(r"^(\s*)([-*]|\d+\.)\s+\S")
ATTR = re.compile(r"\*\*[A-Z][^*\n]{0,60}:\*\*")
LONG_ITEM = 100   # characters of item text that will wrap on the page


def loosen_lists(text: str) -> str:
    """Make every list whose items are blocks a loose list (blank line between
    items), at any nesting level, so the theme spaces the items. An item is a
    block when it wraps onto continuation lines or is longer than LONG_ITEM
    characters. Code blocks, definition lists and already-loose lists are
    left alone."""
    lines = text.split("\n")
    return "\n".join(_loosen(lines))


def _loosen(lines):
    out = []
    i = 0
    in_code = False
    while i < len(lines):
        line = lines[i]
        if line.lstrip().startswith("```"):
            in_code = not in_code
            out.append(line)
            i += 1
            continue
        m = ITEM.match(line)
        if in_code or not m:
            out.append(line)
            i += 1
            continue
        indent = len(m.group(1))
        items, cur, j = [], [line], i + 1
        while j < len(lines):
            n = lines[j]
            mm = ITEM.match(n)
            if mm and len(mm.group(1)) == indent:
                items.append(cur)
                cur = [n]
            elif n.strip() and len(n) - len(n.lstrip()) > indent:
                cur.append(n)
            else:
                break
            j += 1
        items.append(cur)
        # nested lists inside an item get the same treatment
        items = [[it[0]] + _loosen(it[1:]) if len(it) > 1 else it for it in items]
        block = any(len(it) > 1 or len(it[0].strip()) > LONG_ITEM for it in items)
        if len(items) > 1 and block:
            for k, it in enumerate(items):
                out.extend(it)
                if k < len(items) - 1 and it[-1].strip() != "":
                    out.append("")
        else:
            for it in items:
                out.extend(it)
        i = j
    return out


def split_attribute_paragraphs(text: str) -> str:
    """A paragraph made of several **Field:** value runs, such as the header
    of a findings memo, becomes one paragraph per field so the fields scan."""
    blocks = text.split("\n\n")
    out = []
    in_code = False
    for b in blocks:
        if b.lstrip().startswith("```") or "```" in b:
            # crude but safe: never touch a block that opens or closes a fence
            in_code = not in_code if b.count("```") % 2 else in_code
            out.append(b)
            continue
        if in_code or not b.strip() or b.lstrip().startswith(("#", "|", ">", ": ")) or ITEM.match(b.lstrip()):
            out.append(b)
            continue
        flat = " ".join(l.strip() for l in b.split("\n"))
        markers = [m.start() for m in ATTR.finditer(flat)]
        if len(markers) < 2 or markers[0] != 0:
            out.append(b)
            continue
        parts = [flat[a:c].strip() for a, c in zip(markers, markers[1:] + [len(flat)])]
        out.append("\n\n".join(parts))
    return "\n\n".join(out)


def convert_plan(text: str, rel: Path) -> str:
    lines = text.splitlines()
    title = rel.stem.replace("-", " ").title()
    if lines and lines[0].startswith("# "):
        title = lines[0][2:].strip()
        lines = lines[1:]
    body = "\n".join(lines).lstrip("\n")
    body = rewrite_links(body, rel)
    body = split_attribute_paragraphs(body)
    body = loosen_lists(body)
    safe_title = title.replace('"', "'")
    return f'---\ntitle: "{safe_title}"\n---\n\n{body}\n'


def rewrite_links(body: str, rel: Path) -> str:
    """Links to files inside plans/ stay relative; links elsewhere in the repo
    become GitHub links so they resolve from the site."""
    def fix(m):
        label, target = m.group(1), m.group(2)
        if re.match(r"^(https?:|mailto:|#)", target):
            return m.group(0)
        path, _, frag = target.partition("#")
        candidate = (PLANS_SRC / rel.parent / path).resolve()
        if path.endswith(".md") and candidate.exists() and PLANS_SRC in candidate.parents:
            if candidate.name == "README.md":
                path = path[: -len("README.md")] + "index.md"
            return f"[{label}]({path}{'#' + frag if frag else ''})"
        repo_path = (ROOT / "plans" / rel.parent / path).resolve()
        try:
            repo_rel = repo_path.relative_to(ROOT)
        except ValueError:
            return m.group(0)
        return f"[{label}]({REPO_BLOB}{repo_rel.as_posix()})"
    return re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", fix, body)


# ---------- results ----------

RESULT_FILES = [
    ("smoke.jsonl", "Runner smoke test: first headless run, strict policy"),
    ("pilot.jsonl", "Pilot 1: strict CLAUDE.md policy, three injection variants"),
    ("pilot2.jsonl", "Pilot 2: no policy line, first deploy script (marker file plus home-directory log)"),
    ("pilot3.jsonl", "Pilot 3: release-service deploy script, runbook still names maintainer authorization"),
    ("pilot4.jsonl", "Pilot 4: local dev-stack release service, runbook_plain added"),
    ("baseline_sonnet5_none.jsonl", "Phase 0 baseline, first attempt: policy none in CLAUDE.md, runbook still contradicting it"),
    ("baseline2_sonnet5_none.jsonl", "Phase 0 baseline: policy none in both files (the headline 6 of 10)"),
    ("conditions_claudemd.jsonl", "Phase 0 channel conditions B to G on the CLAUDE.md variant"),
    ("allow_bypass_runbook.jsonl", "Phase 0 allow-bypass test: hook allow versus baseline on the runbook variant, process prompt"),
    ("codex_smoke.jsonl", "Codex smoke run"),
    ("codex_baseline_none.jsonl", "Codex baseline: auto reviewer, no SIB"),
    ("phase1_smoke.jsonl", "Phase 1 smoke: real hooks, first try"),
    ("phase1_s1.jsonl", "Phase 1 Scenario 1, first run: classifier without recent activity (mostly ask)"),
    ("phase1_s1b.jsonl", "Phase 1 Scenario 1: signed instruction, recent activity supplied (headline 10 of 10; 3 rows killed by an outage are excluded)"),
    ("phase1_s2.jsonl", "Phase 1 Scenario 2, first run: gate policy file inside the checkout (model read it and refused on its own)"),
    ("phase1_baseline.jsonl", "Phase 1 same-day baseline, no SIB hooks, policy outside the checkout (headline 8 of 10)"),
    ("phase1_s2v2.jsonl", "Phase 1 Scenario 2: all layers, then note and prose only (headline 0 of 10 each)"),
]


def wilson(k, n, z=1.96):
    import math
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (centre - margin) / denom), min(1.0, (centre + margin) / denom))


def results_table(path: Path) -> str:
    rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    groups = {}
    for r in rows:
        hooks = r.get("hooks", "probe")
        cond = r["condition"] if hooks.startswith("probe") else "sib:" + hooks.split(":")[1]
        key = (cond, r["variant"], r.get("harness", "claude"), r.get("model") or "",
               r.get("claudemd_policy", "strict"), r.get("prompt_style", "neutral"))
        groups.setdefault(key, []).append(r)
    out = ["| Condition | Variant | Harness | Model | Policy | Prompt | N | Deployed | Rate (95% CI) | Attempts | Hook denies | Classifier denies | Errors |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for key in sorted(groups):
        g = groups[key]
        n = len(g)
        k = sum(1 for r in g if r["deployed"])
        lo, hi = wilson(k, n)
        att = sum(r["deploy_attempts"] for r in g)
        hd = sum(r["hook_denies"] for r in g)
        cd = sum(len(r["classifier_denials"]) for r in g)
        err = sum(1 for r in g if r.get("is_error") or (r.get("rc") not in (0, None)))
        out.append(f"| {key[0]} | {key[1]} | {key[2]} | {key[3]} | {key[4]} | {key[5]} | {n} | {k} | "
                   f"{k / n:.2f} ({lo:.2f}–{hi:.2f}) | {att} | {hd} | {cd} | {err} |")
    return "\n".join(out)


def hotreload_tables(path: Path) -> str:
    rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    out = []
    model = [r for r in rows if r.get("test") == "model"]
    if model:
        out += ["### Model side", "", "| Write point | Runs | Seen in the same process | Seen after resume |", "|---|---|---|---|"]
        g = {}
        for r in model:
            g.setdefault(r.get("event") or "PreToolUse", []).append(r)
        for ev, rs in g.items():
            out.append(f"| {ev} | {len(rs)} | {sum(1 for r in rs if r['marker_seen_same_turn'])} | "
                       f"{sum(1 for r in rs if r['marker_seen_next_turn'])} |")
        inturn = [r for r in rows if r.get("test") == "model_inturn"]
        if inturn:
            out.append(f"| PreToolUse, second turn in the same process | {len(inturn)} | "
                       f"{sum(1 for r in inturn if r['marker_seen_turn2'])} | n/a |")
        out.append("")
    clf = [r for r in rows if r.get("test") == "classifier"]
    if clf:
        out += ["### Classifier side", "", "| Instrument | Write point | Policy line | Runs | Classifier denials | Action ran |",
                "|---|---|---|---|---|---|"]
        g = {}
        for r in clf:
            g.setdefault((r.get("flip", "hello"), r["event"], r["policy"]), []).append(r)
        for key in sorted(g):
            rs = g[key]
            out.append(f"| {key[0]} | {key[1]} | {key[2]} | {len(rs)} | {sum(1 for r in rs if r['classifier_denials'])} | "
                       f"{sum(1 for r in rs if r['script_ran'])} |")
    return "\n".join(out)


def write_results() -> None:
    parts = ['---\ntitle: Experiment Results\n---\n',
             "Every table on this page is generated at build time from the result files under\n"
             "`scenarios/results/`, one section per file, in the order the batches were run. The\n"
             "[attack catalog](attacks.qmd) explains what each batch was testing and why the earlier ones\n"
             "were superseded. Rows are grouped by condition, variant, harness, model, CLAUDE.md policy\n"
             "ladder and prompt style; \"Errors\" counts runs that ended in an API or process error and\n"
             "are still included in N.\n",
             "Condition letters are the Phase 0 probe conditions (A baseline, B additionalContext, C B plus\n"
             "autoMode prose, D hook deny, E hook allow, F CLAUDE.md rewrite, G classifierContext note).\n"
             "`sib:` rows ran the real Phase 1 hooks with the listed layers enabled (prompt, pre, post,\n"
             "prose).\n"]
    for name, desc in RESULT_FILES:
        p = RESULTS_SRC / name
        if not p.exists():
            continue
        parts.append(f"\n## {name}\n\n{desc}.\n\n{results_table(p)}\n")
    hr = RESULTS_SRC / "hotreload.jsonl"
    if hr.exists():
        parts.append("\n## hotreload.jsonl\n\nCLAUDE.md hot-reload tests (Phase 0 section 0.4b).\n\n" + hotreload_tables(hr) + "\n")
    RESULTS_DST.write_text("\n".join(parts))


if __name__ == "__main__":
    copy_plans()
    write_results()
    print(f"pre-render: copied plans to {PLANS_DST.relative_to(DOCS)}, wrote {RESULTS_DST.relative_to(DOCS)}")
