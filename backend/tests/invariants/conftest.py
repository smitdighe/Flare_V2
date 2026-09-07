"""Re-export the graph rig so the invariant tests exercise the REAL pipeline.

`wire` stubs only the two things that would otherwise touch a model file or a
socket — the providers and the index. The routers, the `@traced` decorator, the
finalize backfill, the grounding and the rules precedence are all the shipped
ones, which is what makes an invariant test here an assertion about the system
rather than about a stub.
"""

from tests.unit.test_graph import HITS, REASON_PAYLOAD, settings, wire  # noqa: F401
