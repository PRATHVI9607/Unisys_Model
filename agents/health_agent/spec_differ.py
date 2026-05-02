"""Enhanced YAML specification differ."""

import json
import hashlib
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class SpecChange:
    """Represents a single spec change."""

    path: str  # e.g., "spec.containers[0].resources.limits.cpu"
    old_value: Any
    new_value: Any
    change_type: str  # "added", "removed", "modified"
    severity: str  # "critical", "high", "medium", "low"


@dataclass
class SpecDiff:
    """Complete diff between two specs."""

    old_spec: Dict[str, Any]
    new_spec: Dict[str, Any]
    changes: List[SpecChange]
    change_count: int
    has_breaking_changes: bool
    summary: str


class SpecDiffer:
    """Detect and explain changes between Kubernetes spec versions."""

    # Breaking changes that require immediate attention
    BREAKING_CHANGES = {
        "spec.template.spec.containers.*.image": "critical",
        "spec.template.spec.containers.*.resources.limits.cpu": "high",
        "spec.template.spec.containers.*.resources.limits.memory": "high",
        "spec.replicas": "medium",
        "spec.template.spec.serviceAccountName": "critical",
        "spec.template.spec.securityContext": "high",
    }

    @staticmethod
    def compute_spec_hash(spec: Dict[str, Any]) -> str:
        """Compute SHA256 hash of spec."""
        spec_json = json.dumps(spec, sort_keys=True, default=str)
        return hashlib.sha256(spec_json.encode()).hexdigest()

    @classmethod
    def diff(
        cls, old_spec: Optional[Dict[str, Any]], new_spec: Dict[str, Any]
    ) -> SpecDiff:
        """Compute diff between old and new specs."""
        if old_spec is None:
            old_spec = {}

        changes = []

        # Compare all keys recursively
        all_keys = set(old_spec.keys()) | set(new_spec.keys())

        for key in all_keys:
            old_val = old_spec.get(key)
            new_val = new_spec.get(key)

            if old_val is None:
                changes.extend(
                    cls._diff_recursive(f"spec.{key}", old_val, new_val, "added")
                )
            elif new_val is None:
                changes.extend(
                    cls._diff_recursive(f"spec.{key}", old_val, new_val, "removed")
                )
            elif old_val != new_val:
                changes.extend(
                    cls._diff_recursive(f"spec.{key}", old_val, new_val, "modified")
                )

        has_breaking = any(c.severity in ("critical", "high") for c in changes)
        summary = cls._generate_summary(changes)

        return SpecDiff(
            old_spec=old_spec,
            new_spec=new_spec,
            changes=changes,
            change_count=len(changes),
            has_breaking_changes=has_breaking,
            summary=summary,
        )

    @classmethod
    def _diff_recursive(
        cls, path: str, old_val: Any, new_val: Any, change_type: str
    ) -> List[SpecChange]:
        """Recursively find all differences."""
        changes = []

        if isinstance(old_val, dict) and isinstance(new_val, dict):
            all_keys = set(old_val.keys()) | set(new_val.keys())
            for key in all_keys:
                old_nested = old_val.get(key)
                new_nested = new_val.get(key)
                nested_path = f"{path}.{key}"

                if old_nested is None:
                    changes.extend(
                        cls._diff_recursive(
                            nested_path, old_nested, new_nested, "added"
                        )
                    )
                elif new_nested is None:
                    changes.extend(
                        cls._diff_recursive(
                            nested_path, old_nested, new_nested, "removed"
                        )
                    )
                elif old_nested != new_nested:
                    changes.extend(
                        cls._diff_recursive(
                            nested_path, old_nested, new_nested, "modified"
                        )
                    )

        elif isinstance(old_val, list) and isinstance(new_val, list):
            if len(old_val) != len(new_val):
                changes.append(
                    SpecChange(
                        path=path,
                        old_value=old_val,
                        new_value=new_val,
                        change_type=change_type,
                        severity=cls._assess_severity(path),
                    )
                )
            else:
                for i, (old_item, new_item) in enumerate(zip(old_val, new_val)):
                    if old_item != new_item:
                        changes.extend(
                            cls._diff_recursive(
                                f"{path}[{i}]", old_item, new_item, change_type
                            )
                        )

        else:
            # Scalar change
            changes.append(
                SpecChange(
                    path=path,
                    old_value=old_val,
                    new_value=new_val,
                    change_type=change_type,
                    severity=cls._assess_severity(path),
                )
            )

        return changes

    @staticmethod
    def _assess_severity(path: str) -> str:
        """Assess severity of a change based on path."""
        path_lower = path.lower()

        if any(x in path_lower for x in ["image", "securitycontext", "serviceaccount"]):
            return "critical"
        elif any(
            x in path_lower for x in ["cpu", "memory", "replicas", "imagepullpolicy"]
        ):
            return "high"
        elif any(x in path_lower for x in ["labels", "annotations", "env", "volume"]):
            return "medium"
        else:
            return "low"

    @staticmethod
    def _generate_summary(changes: List[SpecChange]) -> str:
        """Generate human-readable summary of changes."""
        if not changes:
            return "No spec changes detected"

        added = len([c for c in changes if c.change_type == "added"])
        removed = len([c for c in changes if c.change_type == "removed"])
        modified = len([c for c in changes if c.change_type == "modified"])

        critical = len([c for c in changes if c.severity == "critical"])
        high = len([c for c in changes if c.severity == "high"])

        parts = []
        if added > 0:
            parts.append(f"{added} added")
        if removed > 0:
            parts.append(f"{removed} removed")
        if modified > 0:
            parts.append(f"{modified} modified")

        summary = f"{', '.join(parts)}"

        if critical > 0:
            summary += f" ({critical} critical)"
        if high > 0:
            summary += f" ({high} high)"

        return summary
