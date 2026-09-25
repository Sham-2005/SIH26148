"""
Evidence Correlation Engine
Correlates evidence across processes, files, hashes, network connections, persistence artifacts, and multiple agents.
Produces EvidenceCorrelation clusters referencing underlying Evidence IDs.
"""
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Set
from sqlalchemy.orm import Session
from backend.app.models.models import Evidence, InvestigationIndicator, EvidenceCorrelation

class CorrelationService:
    @classmethod
    def run_case_correlations(cls, case_id: str, db: Session) -> List[EvidenceCorrelation]:
        """Runs multi-dimensional correlation passes over all case evidence and updates database."""
        evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
        if not evidence_items:
            return []

        correlations: List[EvidenceCorrelation] = []
        now = datetime.now(timezone.utc)

        # 1. Cross-Agent Hash Correlation
        # Map sha256_hash -> set of (agent_id, evidence_id)
        hash_to_agents: Dict[str, Set[str]] = {}
        hash_to_evs: Dict[str, Set[str]] = {}

        for ev in evidence_items:
            h = ev.sha256_hash
            if h:
                hash_to_agents.setdefault(h, set()).add(ev.agent_id)
                hash_to_evs.setdefault(h, set()).add(ev.id)

            # Check inside envelope results for secondary hashes
            results = ev.envelope_data.get("results") if ev.envelope_data else None
            if isinstance(results, dict):
                sub_hash = results.get("sha256")
                if sub_hash and isinstance(sub_hash, str) and len(sub_hash) == 64:
                    hash_to_agents.setdefault(sub_hash.lower(), set()).add(ev.agent_id)
                    hash_to_evs.setdefault(sub_hash.lower(), set()).add(ev.id)

        for h, agent_set in hash_to_agents.items():
            if len(agent_set) >= 2:
                # Same hash observed across multiple endpoints!
                corr_id = f"CORR-HASH-{h[:8].upper()}"
                existing = db.query(EvidenceCorrelation).filter(
                    EvidenceCorrelation.case_id == case_id,
                    EvidenceCorrelation.id == corr_id
                ).first()

                agents_list = sorted(list(agent_set))
                ev_list = sorted(list(hash_to_evs[h]))

                title = f"Cross-Agent Hash Concurrency: {h[:12]}... on {len(agents_list)} Endpoints"
                desc = (f"Cryptographic hash {h} was observed concurrently across {len(agents_list)} distinct authorized endpoints "
                        f"({', '.join(agents_list)}). This suggests identical binary deployment or lateral movement.")

                if existing:
                    existing.related_agent_ids = agents_list
                    existing.evidence_ids = ev_list
                    existing.detected_at = now
                    correlations.append(existing)
                else:
                    new_corr = EvidenceCorrelation(
                        id=corr_id,
                        case_id=case_id,
                        correlation_type="SAME_HASH_CROSS_AGENT",
                        title=title,
                        description=desc,
                        primary_agent_id=agents_list[0],
                        related_agent_ids=agents_list,
                        evidence_ids=ev_list,
                        indicators=[h],
                        score=75,
                        detected_at=now
                    )
                    db.add(new_corr)
                    correlations.append(new_corr)

        seen_batch_ids = set()

        # 2. Persistence to Executable / Binary Correlation
        persistence_evs = [ev for ev in evidence_items if "persistence" in ev.collector]
        pe_evs = [ev for ev in evidence_items if "pe_info" in ev.collector or "file.hash" in ev.collector]

        if persistence_evs and pe_evs:
            for p_ev in persistence_evs:
                for pe_ev in pe_evs:
                    if p_ev.agent_id == pe_ev.agent_id:
                        p_suffix = p_ev.id.split("-")[-1]
                        pe_suffix = pe_ev.id.split("-")[-1]
                        corr_id = f"CORR-PERSIST-{p_ev.agent_id}-{p_suffix}-{pe_suffix}"
                        if corr_id in seen_batch_ids:
                            continue
                        seen_batch_ids.add(corr_id)

                        existing = db.query(EvidenceCorrelation).filter(
                            EvidenceCorrelation.case_id == case_id,
                            EvidenceCorrelation.id == corr_id
                        ).first()

                        title = f"Persistence to Binary Inspection Link on {p_ev.agent_id}"
                        desc = (f"Persistence mechanisms on agent '{p_ev.agent_id}' (Evidence {p_ev.id}) "
                                f"correlate with binary inspection evidence ({pe_ev.id}).")

                        ev_list = [p_ev.id, pe_ev.id]
                        if not existing:
                            new_corr = EvidenceCorrelation(
                                id=corr_id,
                                case_id=case_id,
                                correlation_type="PERSISTENCE_EXECUTABLE_LINK",
                                title=title,
                                description=desc,
                                primary_agent_id=p_ev.agent_id,
                                related_agent_ids=[p_ev.agent_id],
                                evidence_ids=ev_list,
                                indicators=[p_ev.collector, pe_ev.collector],
                                score=65,
                                detected_at=now
                            )
                            db.add(new_corr)
                            correlations.append(new_corr)
                        else:
                            correlations.append(existing)

        # 3. Process to Network Outbound Correlation
        proc_evs = [ev for ev in evidence_items if "process" in ev.collector]
        net_evs = [ev for ev in evidence_items if "network" in ev.collector]

        if proc_evs and net_evs:
            for pr in proc_evs:
                for ne in net_evs:
                    if pr.agent_id == ne.agent_id:
                        pr_suffix = pr.id.split("-")[-1]
                        ne_suffix = ne.id.split("-")[-1]
                        corr_id = f"CORR-NETPROC-{pr.agent_id}-{pr_suffix}-{ne_suffix}"
                        if corr_id in seen_batch_ids:
                            continue
                        seen_batch_ids.add(corr_id)

                        existing = db.query(EvidenceCorrelation).filter(
                            EvidenceCorrelation.case_id == case_id,
                            EvidenceCorrelation.id == corr_id
                        ).first()

                        title = f"Process-to-Network Sockets Correlation on {pr.agent_id}"
                        desc = (f"Endpoint {pr.agent_id} exhibits active processes (Evidence {pr.id}) "
                                f"co-occurring with live network sockets (Evidence {ne.id}).")

                        if not existing:
                            new_corr = EvidenceCorrelation(
                                id=corr_id,
                                case_id=case_id,
                                correlation_type="PROCESS_NETWORK_OUTBOUND",
                                title=title,
                                description=desc,
                                primary_agent_id=pr.agent_id,
                                related_agent_ids=[pr.agent_id],
                                evidence_ids=[pr.id, ne.id],
                                indicators=[pr.collector, ne.collector],
                                score=60,
                                detected_at=now
                            )
                            db.add(new_corr)
                            correlations.append(new_corr)
                        else:
                            correlations.append(existing)

        db.commit()
        return correlations
