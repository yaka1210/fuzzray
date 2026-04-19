# FuzzRay

Post-processor for AFL++ fuzzing output. Takes a raw `out/` directory from
`afl-fuzz` and produces a single self-contained HTML report with
deduplicated, CWE-classified, and severity-prioritized issues — plus
fix recommendations and a crashes-over-time chart.

## What it solves

- **Information overload.** AFL++ saves hundreds–thousands of crash files
  per run, most of them duplicates of the same underlying bug. FuzzRay
  collapses them via two-level deduplication (SHA1 of the input, then
  normalized top-N stack hash).
- **Semantic gap.** A raw crash file is just a blob. FuzzRay replays it
  under `gdb --batch`, parses ASan/UBSan stderr, and maps the evidence
  to a CWE distribution, a four-axis behavior taxonomy, and an
  exploitability verdict (inspired by CERT `exploitable`).

## Pipeline

```
Collector → Deduplicator (SHA1 + stack) → Classifier → Prioritizer → Reporter
```

Five independent modules; each step is a pure `list[Crash] -> list[Crash]`
transformation, which keeps the data flow testable.

### Classification

- **Level 1 — CWE.** 10 weaknesses covering MITRE Top 25 memory-safety:
  CWE-787, 125, 416, 119, 476, 190, plus CWE-369, 457, 134, 401. Signal
  priors, ASan/UBSan signatures and gdb-derived heuristics are combined
  into a probability distribution (not a hard label).
- **Level 2 — behavior taxonomy.** Four orthogonal axes per crash:
  `signal_class × crash_site_kind × memory_region × control_flow_state`.
  Any axis can be `unknown`; the others still carry information.
- **Level 3 — exploitability.** `EXPLOITABLE` /
  `PROBABLY_EXPLOITABLE` / `PROBABLY_NOT_EXPLOITABLE` / `UNKNOWN`.

### Severity formula

```
severity = CWE_base × exploit_multiplier × max(confidence, 0.3)
         + log2(duplicate_count + 1)
         + depth_bonus
```

Mapped to `CRITICAL (≥9) / HIGH (≥7) / MEDIUM (≥5) / LOW (<5)`.

## Install

```bash
uv sync                  # creates .venv from uv.lock
uv run fuzzray --help
```

## Usage

```bash
# Basic
uv run fuzzray --afl-out ./out --target ./build/vuln -o report.html

# Fast mode — static classification only, no gdb replay
uv run fuzzray --afl-out ./out --no-replay -o report.html

# With PDF
uv run fuzzray --afl-out ./out --target ./vuln --pdf -o report.html
```

## Validate on the built-in target

[examples/vuln/](examples/vuln/) ships a 60-line C program with three
distinct bugs (CWE-787, CWE-476, CWE-369). It is FuzzRay's ground-truth
corpus: fuzz it for two minutes and the report should contain exactly
three issues with the expected CWEs and severity ordering. See
[examples/vuln/README.md](examples/vuln/README.md) for the exact
commands.

## Layout

```
src/fuzzray/
├── collector.py         # Module 1 — parse AFL++ out/
├── deduplicator.py      # Module 2 — SHA1 + stack hash
├── classifier/          # Module 3 — CWE + taxonomy + exploitability
│   ├── engine.py
│   ├── cwe_rules.py
│   ├── sanitizer.py
│   ├── gdb_runner.py
│   ├── taxonomy.py
│   └── exploitability.py
├── prioritizer.py       # Module 4 — severity scoring
└── reporter/            # Module 5 — Jinja2 HTML + SVG + PDF
    ├── html.py
    ├── pdf.py
    ├── svg_chart.py
    └── templates/report.html.j2
```

## Tests

```bash
uv run pytest
```

Covers collector parsing, both dedup levels, sanitizer classification,
prioritizer ordering, and an end-to-end HTML render.
