<#
.SYNOPSIS
    The Makefile, for Windows PowerShell. PLAN §13.2.

.DESCRIPTION
    `make` is not installed on Windows by default and this project is developed
    on Windows, so a Makefile alone would be a gate nobody could run locally —
    which is how a repository ends up with a commit gate that only CI enforces.

    Every target here runs the IDENTICAL commands to the Makefile target of the
    same name. `tests/ci/test_tooling_parity.py` asserts the two files expose
    the same target list, so the two cannot drift apart silently.

.EXAMPLE
    ./make.ps1              # the default target: check
    ./make.ps1 check        # lint + types + tests
    ./make.ps1 ci           # everything CI runs, in CI's order
    ./make.ps1 help
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Target = 'check'
)

$ErrorActionPreference = 'Stop'

# Prefer the project's own virtualenv when it exists, so `./make.ps1` behaves
# the same whether or not the shell has activated it.
$VenvPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (Test-Path $VenvPython) { $Py = $VenvPython } else { $Py = 'python' }

function Invoke-Step {
    param([string[]]$Arguments)
    Write-Host "==> $Py $($Arguments -join ' ')" -ForegroundColor Cyan
    & $Py @Arguments
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $($Arguments -join ' ')" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

function Step-Lint { Invoke-Step @('-m', 'ruff', 'check', '.') }
function Step-Types { Invoke-Step @('-m', 'mypy', 'app', 'scripts') }
function Step-Test { Invoke-Step @('-m', 'pytest', '-q') }
function Step-TestFast { Invoke-Step @('-m', 'pytest', '-q', '-m', 'not load') }
function Step-TestFailure { Invoke-Step @('-m', 'pytest', '-q', '-m', 'failure') }
function Step-TestLoad { Invoke-Step @('-m', 'pytest', '-q', '-m', 'load') }
function Step-TestInvariants { Invoke-Step @('-m', 'pytest', '-q', '-m', 'invariant') }
function Step-TestContract { Invoke-Step @('-m', 'pytest', '-q', '-m', 'contract') }
function Step-CiChecks { Invoke-Step @('-m', 'scripts.ci.run') }
function Step-Smoke { Invoke-Step @('-m', 'scripts.ci.smoke') }
function Step-Eval { Invoke-Step @('-m', 'scripts.run_eval') }

function Step-Clean {
    Invoke-Step @('-c', "import shutil, pathlib; [shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]")
    Invoke-Step @('-c', "import shutil; [shutil.rmtree(d, ignore_errors=True) for d in ('.pytest_cache', '.ruff_cache', '.mypy_cache', 'build')]")
}

function Show-Help {
    Write-Host 'check          lint + types + tests  (the commit gate)'
    Write-Host 'ci             everything CI runs, in CI''s order'
    Write-Host 'lint           ruff, config-only, never --fix'
    Write-Host 'types          mypy'
    Write-Host 'test           the whole suite, warnings as errors'
    Write-Host 'test-fast      the suite without the load layer'
    Write-Host 'test-failure   the failure-injection layer only'
    Write-Host 'test-load      the load layer only'
    Write-Host 'test-invariants  one named test per PLAN section 5 invariant'
    Write-Host 'test-contract  the frozen-frontend response shapes'
    Write-Host 'ci-checks      disjointness, artifacts, skew, label leak, secrets'
    Write-Host 'smoke          cold-clone smoke test, network blocked'
    Write-Host 'eval           run the held-out eval and cache it (spends quota)'
}

switch ($Target) {
    'help' { Show-Help }
    'lint' { Step-Lint }
    'types' { Step-Types }
    'test' { Step-Test }
    'test-fast' { Step-TestFast }
    'test-failure' { Step-TestFailure }
    'test-load' { Step-TestLoad }
    'test-invariants' { Step-TestInvariants }
    'test-contract' { Step-TestContract }
    'ci-checks' { Step-CiChecks }
    'smoke' { Step-Smoke }
    'eval' { Step-Eval }
    'clean' { Step-Clean }
    'check' {
        Step-Lint
        Step-Types
        Step-Test
        Write-Host "`ncheck: PASSED" -ForegroundColor Green
    }
    'ci' {
        Step-Lint
        Step-Types
        Step-Test
        Step-CiChecks
        Step-Smoke
        Write-Host "`nci: PASSED" -ForegroundColor Green
    }
    default {
        Write-Host "unknown target '$Target'" -ForegroundColor Red
        Show-Help
        exit 2
    }
}
