"""Re-export the graph rig for integration tests that need the real pipeline.

Same reason as `tests/invariants/conftest.py`: `wire` stubs only the providers
and the index, so a test using it exercises the shipped routers, the `@traced`
decorator and the finalize backfill rather than a stub of them.
"""

from tests.unit.test_graph import HITS, REASON_PAYLOAD, settings, wire  # noqa: F401
