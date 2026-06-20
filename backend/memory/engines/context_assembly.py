"""Context assembly engine. Builds a token-budgeted context window, prioritizing
the most similar incidents, threat reports, assets, and IOCs, and dropping
irrelevant memory so we optimize token usage for the LLM."""
from __future__ import annotations

import json
import logging
from typing import Any

from ..config import get_settings
from ..schemas import ContextPackage

log = logging.getLogger(__name__)
_cfg = get_settings()


def _estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 chars/token for English)."""
    return max(1, len(text) // 4)


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def render(pkg: ContextPackage, query_text: str = "") -> tuple[str, int]:
    """Render the ContextPackage as a single LLM-ready prompt section.

    Returns (rendered_text, token_estimate). Stays within CONTEXT_TOKEN_BUDGET.
    """
    budget = _cfg.context_token_budget
    # Reserve chars (~4x tokens) proportionally per section
    char_budget = budget * 4
    lines: list[str] = []

    lines.append("# SOC MEMORY CONTEXT")
    lines.append(f"Query: {query_text or '(alert-driven recall)'}")
    lines.append(f"Sources consulted: {', '.join(pkg.sources_queried) or 'none'}")
    lines.append("")

    # Priority order: similar incidents > threat actors > IOCs > playbook > lessons > graph
    if pkg.similar_incidents:
        lines.append("## Similar Past Incidents")
        for inc in pkg.similar_incidents[:3]:
            lines.append(
                _truncate(
                    f"- [{inc.get('id')}] {inc.get('attack_type','?')} severity={inc.get('severity','?')} "
                    f"root_cause={inc.get('root_cause','-')} resolution={inc.get('resolution','-')}",
                    400,
                )
            )
        lines.append("")

    if pkg.related_threat_actors:
        lines.append("## Related Threat Actors")
        for ta in pkg.related_threat_actors[:4]:
            lines.append(f"- {ta.get('name','-')} (id={ta.get('id','-')})")
        lines.append("")

    if pkg.related_iocs:
        lines.append("## Related IOCs (with risk scores)")
        for ioc in pkg.related_iocs[:5]:
            lines.append(
                f"- {ioc.get('ioc_type','-')} {ioc.get('value','-')} risk={ioc.get('risk_score','-')} "
                f"seen={ioc.get('times_seen','-')}x"
            )
        lines.append("")

    if pkg.recommended_playbook:
        pb = pkg.recommended_playbook
        lines.append("## Recommended Playbook")
        lines.append(
            _truncate(
                f"- {pb.get('name','-')} success_rate={pb.get('success_rate','-')} "
                f"avg_exec={pb.get('avg_execution_sec','-')}s",
                300,
            )
        )
        lines.append("")

    if pkg.lessons:
        lines.append("## Relevant Lessons Learned")
        for ll in pkg.lessons[:3]:
            payload = ll.get("payload", ll)
            lines.append(_truncate(f"- {payload.get('text','') or payload}", 300))
        lines.append("")

    if pkg.blast_radius:
        lines.append("## Graph Blast Radius (lateral movement)")
        for edge in pkg.blast_radius[:6]:
            lines.append(
                f"- {edge.get('from_label','-')} {edge.get('from_id','-')} "
                f"--[{edge.get('rel','-')}]--> {edge.get('to_label','-')} {edge.get('to_id','-')}"
            )
        lines.append("")

    rendered = "\n".join(lines)
    # Final trim to budget
    if _estimate_tokens(rendered) > budget:
        rendered = _truncate(rendered, char_budget)
    return rendered, _estimate_tokens(rendered)
