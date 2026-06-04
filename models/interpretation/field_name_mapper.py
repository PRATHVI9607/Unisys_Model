"""
K8s Field Name Mapper — KubeHeal v4 (Section 06.3)
==================================================
Maps GAT node indices (and their importance/SHAP scores) back to human-readable
K8s field paths recorded at graph-construction time (data.field_paths).
"""

from typing import Dict, List


class FieldNameMapper:
    def map_node_attributions_to_fields(
        self,
        node_attributions: Dict[int, float],
        field_paths: List[str],
    ) -> Dict[str, float]:
        """Return {field_path: score} for the top-10 highest-magnitude nodes."""
        result: Dict[str, float] = {}
        ordered = sorted(node_attributions.items(), key=lambda x: abs(x[1]), reverse=True)
        for node_id, val in ordered[:10]:
            if 0 <= node_id < len(field_paths):
                result[field_paths[node_id]] = val
        return result

    def top_field(self, node_attributions: Dict[int, float], field_paths: List[str]) -> str:
        m = self.map_node_attributions_to_fields(node_attributions, field_paths)
        return next(iter(m), "unknown")

    def format_for_display(self, field_attributions: Dict[str, float]) -> str:
        total = sum(abs(v) for v in field_attributions.values()) + 1e-8
        lines = []
        for field, value in sorted(field_attributions.items(), key=lambda x: abs(x[1]), reverse=True):
            pct = int(100 * abs(value) / total)
            lines.append(f"  {field} ({pct}% of risk)")
        return "\n".join(lines)
