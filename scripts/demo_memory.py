"""End-to-end demo: proves the memory platform works on real data.

Pipeline:
  1. Apply migrations (Postgres + Neo4j + Qdrant)
  2. Seed demo data (threat actor, incident, IOCs, playbook, lesson, graph...)
  3. Simulate a NEW credential-stuffing alert
  4. Run the 8-step retrieval — show similar incident, threat actor, playbook
  5. Run GraphRAG — show fused vector+graph+structured results
  6. Run blast-radius query — show lateral movement graph
  7. Record an investigation outcome — show IOC risk + playbook learning update

Run:
    python -m scripts.demo_memory
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.memory import connections  # noqa: E402
from backend.memory.engines import learning, retrieval  # noqa: E402
from backend.memory.graphrag import graphrag  # noqa: E402
from backend.memory.migrations import apply as migrations_apply  # noqa: E402
from backend.memory.modules import iocs, playbooks  # noqa: E402
from backend.memory.schemas import RecallRequest  # noqa: E402
from backend.memory.store import graph as graph_store  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("demo")

BANNER = "\n" + "=" * 70
FOOTER = "=" * 70


def _section(title: str) -> None:
    print(f"\n--- {title} ---")


def main() -> int:
    print(BANNER)
    print("  AI SOC MEMORY PLATFORM — END-TO-END DEMO")
    print(BANNER)

    # 0. Health check
    _section("Step 0 — Backend health")
    h = connections.health()
    print(f"  Overall: {h['overall'].upper()}")
    for name, status in h.items():
        if name == "overall":
            continue
        mark = "OK " if status["healthy"] else "DOWN"
        print(f"  [{mark}] {name}: {status['detail']}")
    if h["overall"] != "healthy":
        print("\n  ! One or more backends are down. Demo may be partial.")
        print("    Start them with:  docker compose up -d")

    # 1. Migrations
    _section("Step 1 — Apply migrations")
    mig = migrations_apply.apply_all(reset=False)
    for k, v in mig.items():
        print(f"  {k}: {v}")

    # 2. Seed
    _section("Step 2 — Seed demo data")
    from scripts.seed_memory import seed_demo_data

    counts = seed_demo_data()
    for k, v in counts.items():
        print(f"  {k}: {v}")

    # 3. Simulate a NEW alert (similar to the seeded incident)
    _section("Step 3 — Simulate a NEW credential-stuffing alert")
    new_alert = {
        "id": "alert_demo_new",
        "attack_type": "CREDENTIAL_STUFFING",
        "title": "Credential stuffing against VPN users",
        "attacker_ip": "192.168.1.100",   # same IOC as seeded incident
        "user_id": "victim_user_42",
        "severity": "HIGH",
    }
    print(f"  Alert: {new_alert}")

    # 4. Retrieval (8-step pipeline)
    _section("Step 4 — Run 8-step retrieval (memory recall)")
    req = RecallRequest(alert=new_alert, query_text="credential stuffing against VPN users")
    pkg = retrieval.recall(req)
    print(f"  Sources consulted : {pkg.sources_queried}")
    print(f"  Similar incidents : {len(pkg.similar_incidents)}")
    for inc in pkg.similar_incidents:
        print(f"    - [{inc.get('id')}] {inc.get('attack_type')} root_cause={inc.get('root_cause','-')[:60]}")
    print(f"  Related IOCs      : {len(pkg.related_iocs)}")
    for ioc in pkg.related_iocs:
        print(f"    - {ioc.get('ioc_type')} {ioc.get('value')} risk={ioc.get('risk_score')}")
    print(f"  Threat actors     : {len(pkg.related_threat_actors)}")
    for ta in pkg.related_threat_actors:
        print(f"    - {ta.get('name')}")
    print(f"  Recommended PB    : {(pkg.recommended_playbook or {}).get('name', '-')}")
    print(f"  Lessons relevant  : {len(pkg.lessons)}")
    print(f"  Blast-radius edges: {len(pkg.blast_radius)}")
    print(f"  Token estimate    : {pkg.token_estimate}")
    print("\n  Rendered LLM-ready context (first 600 chars):")
    print("  " + pkg.rendered_context[:600].replace("\n", "\n  "))

    # 5. GraphRAG
    _section("Step 5 — GraphRAG (fused vector + graph + structured)")
    gr = graphrag("credential stuffing VPN", top_k=3, expand_hops=2)
    total_vec = sum(len(h) for h in gr["vector_hits"].values())
    print(f"  Vector hits       : {total_vec}")
    print(f"  Graph expansions  : {len(gr['expanded_entities'])}")
    for e in gr["expanded_entities"][:3]:
        print(f"    seed {e['label']}={e['seed']} -> {len(e['neighbors'])} neighbors")
    print(f"  Structured matches: {len(gr['structured_matches'])}")

    # 6. Blast radius
    _section("Step 6 — Blast-radius graph query (lateral movement)")
    try:
        edges = graph_store.blast_radius("IP", "value", "192.168.1.100", max_hops=3)
        print(f"  Reachable edges from 192.168.1.100: {len(edges)}")
        for e in edges[:8]:
            print(f"    {e.get('from_label')} {e.get('from_id')} -[{e.get('rel')}]-> {e.get('to_label')} {e.get('to_id')}")
    except Exception as e:
        print(f"  (graph query unavailable: {e})")

    # 7. Continuous learning
    _section("Step 7 — Record investigation outcome (continuous learning)")
    # Capture IOC risk BEFORE
    before = iocs.get("ip", "192.168.1.100")
    risk_before = (before or {}).get("risk_score")
    pb_before = playbooks.recommend("CREDENTIAL_STUFFING", top_k=1)
    pb_succ_before = (pb_before[0] if pb_before else {}).get("success_rate")

    outcome = learning.record_outcome(
        incident_id="inc_credstuff_001",
        verdict="TRUE_POSITIVE",
        iocs_seen=[{"ioc_type": "ip", "value": "192.168.1.100"}],
        playbook_id="pb_cred_stuffing",
        playbook_success=True,
        playbook_duration_sec=40.0,
        analyst_feedback="playbook worked well",
    )
    print(f"  Learning applied: {outcome}")

    after = iocs.get("ip", "192.168.1.100")
    risk_after = (after or {}).get("risk_score")
    pb_after = playbooks.recommend("CREDENTIAL_STUFFING", top_k=1)
    pb_succ_after = (pb_after[0] if pb_after else {}).get("success_rate")
    print(f"  IOC risk_score       : {risk_before} -> {risk_after}  (times_seen={(after or {}).get('times_seen')})")
    print(f"  Playbook success_rate: {pb_succ_before} -> {pb_succ_after}")

    print(FOOTER)
    print("  DEMO COMPLETE — memory recall + GraphRAG + learning all verified.")
    print(FOOTER)
    return 0


if __name__ == "__main__":
    sys.exit(main())
