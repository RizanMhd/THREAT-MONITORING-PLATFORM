from typing import Dict, Any
from app.models import Event


class RiskScoringService:
    SEVERITY_WEIGHTS = {
        "Low": 10,
        "Medium": 30,
        "High": 82,
        "Critical": 90,
    }

    ASSET_CRITICALITY_WEIGHTS = {
        "low": 0.5,
        "medium": 1.0,
        "high": 1.5,
        "critical": 2.0,
    }

    IMPACT_WEIGHTS = {
        "low": 0.5,
        "medium": 1.0,
        "high": 1.5,
        "critical": 2.0,
    }

    def calculate_risk_score(
        self,
        rule_id: str,
        event: Event,
        severity: str,
        asset_criticality: str = "medium",
        detection_confidence: float = 0.8,
        event_frequency: int = 1,
    ) -> float:
        severity_key = severity.capitalize()
        base_score = self.SEVERITY_WEIGHTS.get(severity_key, 30)

        asset_multiplier = self.ASSET_CRITICALITY_WEIGHTS.get(asset_criticality, 1.0)
        impact_multiplier = self.IMPACT_WEIGHTS.get("medium", 1.0)

        confidence_factor = detection_confidence

        frequency_factor = min(1.0 + (event_frequency - 1) * 0.1, 2.0)

        score = base_score * asset_multiplier * impact_multiplier * confidence_factor * frequency_factor

        return min(max(score, 0), 100)

    @staticmethod
    def get_severity_classification(score: float) -> str:
        if score >= 85:
            return "Critical"
        elif score >= 65:
            return "High"
        elif score >= 35:
            return "Medium"
        else:
            return "Low"

    def get_scoring_factors(self) -> Dict[str, Any]:
        return {
            "threat_severity": {
                "description": "Base severity associated with the triggering detection rule",
                "weights": self.SEVERITY_WEIGHTS,
            },
            "asset_criticality": {
                "description": "Configured criticality of the affected resource/asset",
                "weights": self.ASSET_CRITICALITY_WEIGHTS,
            },
            "detection_confidence": {
                "description": "Confidence that the correlated events represent a genuine threat",
                "range": "0.0 - 1.0",
            },
            "event_frequency": {
                "description": "Number and rate of related events within the correlation window",
                "factor": "min(1.0 + (count - 1) * 0.1, 2.0)",
            },
            "potential_impact": {
                "description": "Estimated consequence if the incident is not addressed",
                "weights": self.IMPACT_WEIGHTS,
            },
        }