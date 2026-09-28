# Contributing to WireScope

## Setup

```bash
git clone https://github.com/yigitatmaca42/WireScope.git
cd WireScope
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

This installs WireScope itself (editable) plus `pytest`, `ruff`, and
`mypy`.

## Running the test suite

```bash
pytest
pytest -v                      # verbose
pytest tests/test_analyzer.py  # a single file
```

The suite generates its own small synthetic packets with Scapy at test
time (see `tests/conftest.py`) - it never depends on a real, potentially
sensitive PCAP file.

## Linting and type-checking

```bash
ruff check .        # lint
ruff format .        # format (if you want ruff's formatter; black also works)
mypy wirescope        # type-check
```

CI runs `ruff check` and `pytest` on Python 3.11, 3.12, and 3.13 - please
make sure both pass locally before opening a PR.

## Trying it end-to-end

```bash
python examples/generate_sample_pcap.py
wirescope examples/sample_capture.pcap --findings
wirescope examples/sample_capture.pcap --json /tmp/report.json --csv /tmp/reports --html /tmp/report.html
```

## Code style

- Python 3.11+, type hints everywhere reasonable, `from __future__ import
  annotations` at the top of every module.
- Dataclasses for data, plain functions for behavior - avoid classes that
  exist only to hold a bag of methods with no real state.
- The analyzer (`analyzer.py`) produces **facts only**. Anything that
  interprets those facts (heuristics, IOC matching) lives in `detection/`
  and must not be imported by `analyzer.py`. If you're adding a new
  heuristic, it belongs in `detection/heuristics.py`, phrased with hedged
  language (*Possible*, *Potential*, *Observed*) - see the README's
  Detection Philosophy section for why.
- No bare `except:` clauses, no silently-swallowed exceptions. If a
  parser hits malformed input, return `None` and let the caller decide.
- Public functions get a docstring explaining *why*, not a restatement of
  the function name. Skip comments that just describe what the next line
  obviously does.

## Pull requests

- Keep PRs focused - one feature or fix per PR is easier to review than a
  bundle of unrelated changes.
- Add or update tests for anything you change; `assert True`-style
  placeholder tests will be asked to be replaced with real assertions.
- If you're adding a new heuristic finding, add a `tests/test_heuristics.py`
  case that constructs the minimal `AnalysisResult` needed to trigger it
  (see the existing tests there for the pattern) - you don't need a full
  PCAP fixture for this.
- Update `CHANGELOG.md` under an "Unreleased" heading if your change is
  user-visible.
