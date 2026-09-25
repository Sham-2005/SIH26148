"""
Explainable Risk & Priority Engine
Calculates deterministic, auditable threat priority scores based on observable forensic factors.
Every score includes an itemized, human-readable justification ledger (no opaque AI or hallucinations).
"""
from typing import Dict, Any, List, Tuple

class RiskService:
    @classmethod
    def evaluate_risk(
        cls,
        evidence_count: int = 1,
        has_persistence: bool = False,
        has_network_connection: bool = False,
        has_suspicious_location: bool = False,
        cross_agent_count: int = 1,
        has_known_tool_keyword: bool = False,
        custom_factors: List[str] = None
    ) -> Tuple[str, int, List[str]]:
        """
        Calculates priority category, numerical score (0-100), and explanation reasons.
        Returns: (priority_str, score_int, reasons_list)
        """
        score = 10
        reasons: List[str] = []

        if has_persistence:
            score += 30
            reasons.append("+30: Defensive persistence mechanism observed (Registry RunKey, Service, or Cron)")

        if cross_agent_count > 1:
            points = min(30, 15 * (cross_agent_count - 1))
            score += points
            reasons.append(f"+{points}: Identical indicator/artifact observed across {cross_agent_count} endpoints")

        if has_suspicious_location:
            score += 25
            reasons.append("+25: Executable or script located in temporary/writable staging directory (Temp/AppData)")

        if has_network_connection:
            score += 20
            reasons.append("+20: Active remote network connection or listening socket associated")

        if has_known_tool_keyword:
            score += 25
            reasons.append("+25: Security tool / offensive framework keyword observed in telemetry")

        if evidence_count >= 3:
            score += 10
            reasons.append(f"+10: High correlation cluster ({evidence_count} corroborating evidence envelopes)")

        if custom_factors:
            for factor in custom_factors:
                score += 10
                reasons.append(f"+10: {factor}")

        score = max(0, min(100, score))

        if score >= 75:
            priority = "CRITICAL"
        elif score >= 50:
            priority = "HIGH"
        elif score >= 30:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        return priority, score, reasons
