"""Deterministic routing from files to security agents.

Replaces the previous triage LLM call. The current implementation returns
the full set of framework-relevant agents for every file — matching what
the old triage step did on its failure path — but the contract is designed
so future rule-based filtering (extension + framework → agent domains) can
slot in without touching the workflow graph.

Keeping this as a pure function (no I/O, no LLM, no DB) makes it cheap,
testable, and easy to extend. When we have enough scan data to know which
agents matter for which file patterns, add a rules list here or load from
a dedicated `agent_routing_rules` table.
"""

from typing import Any, Dict, List


def resolve_agents_for_file(
    file_path: str,
    all_relevant_agents: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Return the agents to run against this file.

    Args:
        file_path: the file being analyzed (used by future pattern-based rules).
        all_relevant_agents: mapping of agent_name → RelevantAgent dict. The
            caller has already filtered by selected frameworks; this function
            narrows further by file characteristics.

    Returns:
        List of RelevantAgent dicts to run against the file. Empty list means
        "skip this file."
    """
    # Current policy: apply every framework-relevant agent. Fast and safe; a
    # modern model running an irrelevant agent against a file simply returns
    # no findings, and we avoid the previous per-file triage LLM call
    # (~1 extra round-trip per file, ~$cost, ~latency, plus a failure mode).
    del file_path  # Reserved for future rule-based filtering.
    return list(all_relevant_agents.values())
