"""Scope and authorization boundary enforcement for RootScan."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Set

from app.security.validation import ValidationResult, validate_target


@dataclass
class AuthorizedScope:
    scope_id: str
    target: str
    target_type: str
    authorized_ips: Set[str] = field(default_factory=set)
    allow_private: bool = False
    authorized_at: datetime = field(default_factory=datetime.utcnow)
    authorized_by: str = "Operator"
    notes: Optional[str] = None


class ScopeManager:
    """Enforces assessment boundaries and authorization confirmation."""

    def __init__(self, allow_private_default: bool = False):
        self.allow_private_default = allow_private_default
        self.active_scopes: dict[str, AuthorizedScope] = {}

    def register_scope(
        self,
        raw_target: str,
        allow_private: Optional[bool] = None,
        operator: str = "Operator",
        notes: Optional[str] = None
    ) -> tuple[bool, Optional[AuthorizedScope], str]:
        """
        Validate and register an authorized scope for assessment.
        Returns: (success: bool, scope: Optional[AuthorizedScope], message: str)
        """
        permit_private = self.allow_private_default if allow_private is None else allow_private
        val: ValidationResult = validate_target(raw_target, allow_private=permit_private)

        if not val.is_valid:
            return False, None, val.error_message or "Scope validation failed."

        scope_id = f"SCOPE-{val.normalized_target}"
        scope = AuthorizedScope(
            scope_id=scope_id,
            target=val.normalized_target,
            target_type=val.target_type.value,
            authorized_ips=set(val.resolved_ips),
            allow_private=permit_private,
            authorized_by=operator,
            notes=notes
        )
        self.active_scopes[scope.target] = scope
        return True, scope, "Target successfully authorized."

    def is_in_scope(self, candidate_host_or_ip: str, parent_target: str) -> bool:
        """
        Verify if a given destination falls strictly within the registered scope of parent_target.
        Prevents lateral creep or out-of-scope pivots during scanning.
        """
        scope = self.active_scopes.get(parent_target.lower())
        if not scope:
            return False

        candidate = candidate_host_or_ip.lower().strip()
        if candidate == scope.target:
            return True

        if candidate in scope.authorized_ips:
            return True

        return False

