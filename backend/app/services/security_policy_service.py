"""
Security Policy & Data Protection Engine
Enforces role-based action authorizations, immutable resource barriers,
analyst approval requirements, and sensitive secret redaction.
"""
from typing import Dict, Any, Tuple, Optional, Set, List
import re

SENSITIVE_KEY_PATTERNS = {
    "password", "secret", "token", "auth_token", "api_key",
    "private_key", "credentials", "access_token", "authorization"
}

# Standardized Role Definitions
ROLES = {"ADMIN", "ANALYST", "OPERATOR", "AGENT"}

# Granular Security Policy Matrix
SECURITY_POLICIES: Dict[str, Dict[str, Any]] = {
    # Playbooks
    "create_playbook": {
        "allowed_roles": {"ADMIN", "ANALYST"},
        "requires_approval": False,
        "requires_audit": True,
        "description": "Authoring new defensive response playbooks"
    },
    "approve_playbook": {
        "allowed_roles": {"ADMIN", "ANALYST"},
        "disallowed_roles": {"AGENT", "OPERATOR"},
        "requires_approval": False,
        "requires_audit": True,
        "description": "Authorizing defensive playbook execution"
    },
    "execute_playbook": {
        "allowed_roles": {"ADMIN", "OPERATOR", "ANALYST"},
        "disallowed_roles": {"AGENT"},
        "requires_approval": True,
        "requires_audit": True,
        "description": "Executing approved response playbook steps"
    },

    # Evidence & Reports
    "submit_evidence": {
        "allowed_roles": {"AGENT"},
        "requires_approval": False,
        "requires_audit": True,
        "description": "Endpoint posting cryptographically sealed evidence"
    },
    "modify_evidence": {
        "allowed_roles": set(),  # Immutable! Nobody can modify evidence
        "requires_approval": False,
        "requires_audit": True,
        "description": "Modification of stored forensic evidence envelopes"
    },
    "generate_report": {
        "allowed_roles": {"ADMIN", "ANALYST"},
        "requires_approval": False,
        "requires_audit": True,
        "description": "Compiling and exporting court-admissible forensic reports"
    },

    # Threat Intelligence & Cases
    "modify_threat_intel": {
        "allowed_roles": {"ADMIN", "ANALYST"},
        "disallowed_roles": {"AGENT", "OPERATOR"},
        "requires_approval": False,
        "requires_audit": True,
        "description": "Ingesting or modifying STIX/TAXII threat feeds"
    },
    "resolve_security_event": {
        "allowed_roles": {"ADMIN", "ANALYST"},
        "disallowed_roles": {"AGENT"},
        "requires_approval": False,
        "requires_audit": True,
        "description": "Marking tamper or security alerts as resolved"
    },
    "modify_audit_log": {
        "allowed_roles": set(),  # Immutable! Nobody can modify audit log
        "requires_approval": False,
        "requires_audit": True,
        "description": "Altering or deleting past audit log entries"
    }
}


def redact_sensitive_data(data: Any) -> Any:
    """
    Recursively scrubs sensitive authentication tokens, passwords, and private keys
    from logging payloads, audit records, and export files.
    """
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if isinstance(v, (dict, list)):
                cleaned[k] = redact_sensitive_data(v)
            elif any(pattern in k_lower for pattern in SENSITIVE_KEY_PATTERNS):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = redact_sensitive_data(v)
        return cleaned
    elif isinstance(data, list):
        return [redact_sensitive_data(item) for item in data]
    elif isinstance(data, str):
        # Quick regex check for JWT-like structures (three base64 segments)
        if len(data) > 50 and re.match(r"^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$", data):
            return "[REDACTED_JWT]"
        return data
    return data


class SecurityPolicyService:
    @classmethod
    def evaluate_policy(
        cls,
        action: str,
        role: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, str, Dict[str, Any]]:
        """
        Evaluates role-based authorization and environmental security constraints.
        Returns: (decision, reason, details)
        decision in: 'ALLOW', 'DENY', 'REQUIRES_APPROVAL'
        """
        role_normalized = (role or "").upper()
        policy = SECURITY_POLICIES.get(action)

        if not policy:
            # Safe default: reject unknown action
            return "DENY", f"Action '{action}' has no registered security policy.", {"action": action, "role": role_normalized}

        # 1. Immutable resource check (e.g. modify_evidence, modify_audit_log)
        if len(policy.get("allowed_roles", set())) == 0:
            return "DENY", f"Action '{action}' is strictly prohibited. Forensic resources are immutable.", {
                "action": action,
                "immutable": True
            }

        # 2. Check explicit disallowed roles
        if role_normalized in policy.get("disallowed_roles", set()):
            return "DENY", f"Role '{role_normalized}' is explicitly forbidden from performing '{action}'.", {
                "action": action,
                "role": role_normalized
            }

        # 3. Check allowed roles
        if role_normalized not in policy.get("allowed_roles", set()) and role_normalized != "ADMIN":
            return "DENY", f"Role '{role_normalized}' lacks permission for '{action}'. Requires: {policy['allowed_roles']}", {
                "action": action,
                "role": role_normalized,
                "allowed_roles": list(policy["allowed_roles"])
            }

        # 4. Check approval requirement
        if policy.get("requires_approval", False):
            context = context or {}
            is_approved = context.get("is_approved", False)
            if not is_approved:
                return "REQUIRES_APPROVAL", f"Action '{action}' requires formal analyst authorization prior to execution.", {
                    "action": action,
                    "requires_approval": True
                }

        return "ALLOW", f"Action '{action}' authorized for role '{role_normalized}'.", {
            "action": action,
            "role": role_normalized,
            "audit_required": policy.get("requires_audit", True)
        }

    @classmethod
    def check_permission(cls, role: str, action: str) -> bool:
        """Convenience method checking whether a given role can perform an action."""
        role_u = role.upper()
        act_u = action.upper()
        if role_u == "ADMIN":
            return True
        if role_u == "ANALYST":
            return act_u in ("REPORT_GENERATE", "EVIDENCE_VERIFY", "PLAYBOOK_CREATE", "TASK_CREATE")
        if role_u == "OPERATOR":
            return act_u in ("PLAYBOOK_EXECUTE", "TASK_EXECUTE")
        if role_u == "AGENT":
            return act_u in ("EVIDENCE_SUBMIT", "TASK_POLL", "HEARTBEAT")
        return False

    @classmethod
    def evaluate_action(
        cls,
        actor_role: str,
        action: str,
        resource_type: str,
        resource_id: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Evaluates an action and returns a dictionary with decision and reason."""
        context = context or {}
        role_u = actor_role.upper()
        act_u = action.upper()

        # 1. Check immutable resources
        if context.get("sealed") is True or act_u in ("EVIDENCE_DELETE", "AUDIT_DELETE"):
            return {
                "decision": "DENY",
                "reason": f"Immutable resource: '{resource_id}' cannot be modified or deleted."
            }

        # 2. Check actions requiring approval
        if act_u in ("HOST_ISOLATION", "CONTAINMENT_EXECUTE") or context.get("requires_dual_authorization"):
            return {
                "decision": "REQUIRES_APPROVAL",
                "reason": f"Action '{action}' requires formal approval."
            }

        # 3. Check role boundaries
        if not cls.check_permission(role_u, act_u):
            return {
                "decision": "DENY",
                "reason": f"Role '{role_u}' not authorized to perform '{action}'."
            }

        return {
            "decision": "ALLOW",
            "reason": f"Action '{action}' authorized for role '{role_u}'."
        }

    @classmethod
    def redact_sensitive_data(cls, data: Any) -> Any:
        """Redacts sensitive credentials from input data."""
        return redact_sensitive_data(data)
