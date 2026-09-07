# Flare backend — the local half of CI. PLAN §13.2.
#
# `make check` runs lint, types and tests, which is the gate every commit has to
# pass. `make ci` runs everything the GitHub Actions workflow runs, in the same
# order, calling the same modules — so a green board on a workstation means the
# same thing as a green board on a runner.
#
# WINDOWS: `make` is not installed by default. `./make.ps1 <target>` in
# PowerShell runs the identical commands; every target here has a matching one
# there and a test asserts the two lists agree.

PY ?= python
PYTEST ?= $(PY) -m pytest

.DEFAULT_GOAL := check
.PHONY: help check ci lint types test test-fast test-failure test-load \
        test-invariants test-contract ci-checks smoke eval clean

help:
	@echo "check          lint + types + tests  (the commit gate)"
	@echo "ci             everything CI runs, in CI's order"
	@echo "lint           ruff, config-only, never --fix"
	@echo "types          mypy"
	@echo "test           the whole suite, warnings as errors"
	@echo "test-fast      the suite without the load layer"
	@echo "test-failure   the failure-injection layer only"
	@echo "test-load      the load layer only"
	@echo "test-invariants  one named test per PLAN §5 invariant"
	@echo "test-contract  the frozen-frontend response shapes"
	@echo "ci-checks      disjointness, artifacts, skew, label leak, secrets"
	@echo "smoke          cold-clone smoke test, network blocked"
	@echo "eval           run the held-out eval and cache it (spends quota)"

# -- the commit gate --------------------------------------------------------

check: lint types test

# -- individual gates -------------------------------------------------------

# PLAN §13.2 names ruff the LINTER, config-only, never --fix. `ruff format
# --check` is deliberately NOT here: it is a different gate, it would demand
# reformatting 107 files written across Phases 1-6 to a style nobody chose,
# and a formatting sweep does not belong in the phase that adds CI.
lint:
	$(PY) -m ruff check .

types:
	$(PY) -m mypy app scripts

test:
	$(PYTEST) -q

test-fast:
	$(PYTEST) -q -m "not load"

test-failure:
	$(PYTEST) -q -m failure

test-load:
	$(PYTEST) -q -m load

test-invariants:
	$(PYTEST) -q -m invariant

test-contract:
	$(PYTEST) -q -m contract

ci-checks:
	$(PY) -m scripts.ci.run

smoke:
	$(PY) -m scripts.ci.smoke

# -- everything CI runs, in CI's order --------------------------------------

ci: lint types test ci-checks smoke

# -- not part of any gate ---------------------------------------------------
#
# `eval` spends real provider quota and can trip a guard band, so it is never
# run by CI. It is here because it is the command PLAN §19 step 8 asks an
# operator to run before a rehearsal.
eval:
	$(PY) -m scripts.run_eval

clean:
	$(PY) -c "import shutil, pathlib; [shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]"
	$(PY) -c "import shutil; [shutil.rmtree(d, ignore_errors=True) for d in ('.pytest_cache', '.ruff_cache', '.mypy_cache', 'build')]"
