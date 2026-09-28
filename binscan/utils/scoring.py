"""
Risk scoring untuk hasil scan.
Mengubah indikasi mencurigakan menjadi skor 0-100.
"""

from ..config import (
    RISK_WEIGHTS,
    RISK_LEVELS,
    SUSPICIOUS_API_COMBOS,
)


class RiskScorer:
    """Hitung skor risiko dari hasil scan."""

    @staticmethod
    def score(results: dict) -> dict:
        """
        Hitung skor risiko & level.
        Returns: {"score": int, "level": str, "reasons": list}
        """
        score = 0
        reasons = []

        # 1. Suspicious strings
        strings = results.get("suspicious_strings", [])
        if strings:
            weight = RISK_WEIGHTS["suspicious_string"]
            contribution = min(len(strings), 5) * weight
            score += contribution
            reasons.append(f"{len(strings)} suspicious strings (+{contribution})")

        # 2. YARA matches (bobot paling tinggi)
        yara = results.get("yara_matches", [])
        if yara:
            weight = RISK_WEIGHTS["yara_match"]
            contribution = len(yara) * weight
            score += contribution
            reasons.append(f"{len(yara)} YARA rule match (+{contribution})")

        # 3. Packer
        if results.get("packer_detected"):
            weight = RISK_WEIGHTS["packer_detected"]
            score += weight
            reasons.append(f"Packer detected: {results['packer_detected']} (+{weight})")

        # 4. High entropy
        entropy = results.get("entropy", 0)
        if entropy > 7.5:
            weight = RISK_WEIGHTS["high_entropy"]
            score += weight
            reasons.append(f"High entropy: {entropy:.2f} (+{weight})")

        # 5. Suspicious API combo (RAT indicator)
        imports = results.get("imports", {})
        all_apis = set()
        for funcs in imports.values():
            all_apis.update(funcs)

        for combo in SUSPICIOUS_API_COMBOS:
            if all(api in all_apis for api in combo):
                weight = RISK_WEIGHTS["api_combo"]
                score += weight
                reasons.append(f"API combo: {'+'.join(combo[:2])}... (+{weight})")
                break

        # Cap di 100
        score = min(score, 100)

        # Tentukan level
        level = "CLEAN"
        for threshold, name in RISK_LEVELS:
            if score >= threshold:
                level = name

        return {
            "score": score,
            "level": level,
            "reasons": reasons,
        }

    @staticmethod
    def format_display(scoring: dict) -> str:
        """Format skor untuk ditampilkan di terminal."""
        level = scoring["level"]
        score = scoring["score"]

        colors = {
            "CLEAN": "green",
            "LOW": "green",
            "MEDIUM": "yellow",
            "HIGH": "red",
            "CRITICAL": "bold red",
        }
        color = colors.get(level, "white")

        return f"[{color}]{level} ({score}/100)[/{color}]"