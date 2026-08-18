import re

from fastapi import FastAPI
from typing import Any


app = FastAPI()

# ============================================================
# Task 2 — LLM Action Firewall
# ============================================================

ASSIGNED_TENANT = "tenant-imbk5c0"
ALLOWED_EMAIL_DOMAIN = "notify-12r3kcs.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html",
}


def block(reason: str):
    return {
        "decision": "block",
        "reason": reason,
    }


def allow():
    return {
        "decision": "allow",
        "reason": "ALLOW",
    }


def is_unsafe_html(html: str) -> bool:
    lower = html.lower()

    if "<script" in lower:
        return True

    if "<iframe" in lower:
        return True

    if "javascript:" in lower:
        return True

    if re.search(r"\bon[a-z]+\s*=", lower):
        return True

    return False


@app.post("/action-firewall")
def action_firewall(request: dict[str, Any]):
    # 1. Top-level schema
    required = {
        "provenance",
        "humanApproved",
        "action",
    }

    if not required.issubset(request.keys()):
        return block("INVALID_SCHEMA")

    if not isinstance(request["provenance"], str):
        return block("INVALID_SCHEMA")

    if request["provenance"] not in {"trusted", "untrusted"}:
        return block("INVALID_SCHEMA")

    if not isinstance(request["humanApproved"], bool):
        return block("INVALID_SCHEMA")

    if "untrustedContent" in request:
        if request["untrustedContent"] is not None and not isinstance(
            request["untrustedContent"], str
        ):
            return block("INVALID_SCHEMA")

    if not isinstance(request["action"], dict):
        return block("INVALID_SCHEMA")

    action = request["action"]

    if "tool" not in action or "args" not in action:
        return block("INVALID_SCHEMA")

    if not isinstance(action["tool"], str):
        return block("INVALID_SCHEMA")

    if not isinstance(action["args"], dict):
        return block("INVALID_SCHEMA")

    # 2. Tool allowlist
    tool = action["tool"]

    if tool not in ALLOWED_TOOLS:
        return block("TOOL_NOT_ALLOWED")

    args = action["args"]

    # 3. Selected tool argument schema
    if tool == "search":
        if set(args.keys()) != {"query"}:
            return block("INVALID_SCHEMA")

        if not isinstance(args["query"], str):
            return block("INVALID_SCHEMA")

        if not 1 <= len(args["query"]) <= 200:
            return block("INVALID_SCHEMA")

    elif tool == "lookup_record":
        if set(args.keys()) != {"tenantId", "recordId"}:
            return block("INVALID_SCHEMA")

        if not isinstance(args["tenantId"], str):
            return block("INVALID_SCHEMA")

        if not isinstance(args["recordId"], str) or args["recordId"] == "":
            return block("INVALID_SCHEMA")

    elif tool == "send_email":
        if set(args.keys()) != {"to", "subject", "body"}:
            return block("INVALID_SCHEMA")

        if not all(isinstance(args[key], str) for key in ("to", "subject", "body")):
            return block("INVALID_SCHEMA")

    elif tool == "render_html":
        if set(args.keys()) != {"html"}:
            return block("INVALID_SCHEMA")

        if not isinstance(args["html"], str):
            return block("INVALID_SCHEMA")

    # 4. Tenant scope
    if tool == "lookup_record":
        if args["tenantId"] != ASSIGNED_TENANT:
            return block("TENANT_SCOPE")

    # 5. Egress
    if tool == "send_email":
        recipient = args["to"]

        if "@" not in recipient:
            return block("EGRESS_DENIED")

        local, domain = recipient.rsplit("@", 1)

        if not local or domain != ALLOWED_EMAIL_DOMAIN:
            return block("EGRESS_DENIED")

    # 6. Approval
    if tool == "send_email":
        if request["humanApproved"] is not True:
            return block("APPROVAL_REQUIRED")

    # 7. HTML safety
    if tool == "render_html":
        if is_unsafe_html(args["html"]):
            return block("UNSAFE_OUTPUT")

    return allow()


# ============================================================
# Task 3 — Terraform Plan Policy Gate
# ============================================================

PRODUCTION_WORKSPACE = "prod-3tjh6a"

REQUIRED_LABELS = {
    "owner": "student-q2nu4",
    "environment": "production",
    "cost_center": "cc-h6sj",
}

ALLOWED_BACKENDS = {
    "gcs",
    "s3",
    "azurerm",
    "remote",
}

DESTRUCTIVE_RESOURCE_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}

ALLOWED_ACTIONS = {
    "create",
    "update",
    "delete",
}


def terraform_reject(reason: str):
    return {
        "decision": "reject",
        "reason": reason,
    }


def terraform_approve():
    return {
        "decision": "approve",
        "reason": "APPROVE",
    }


def valid_string(value):
    return isinstance(value, str)


def valid_bool(value):
    # bool is a subclass of int in Python, so explicitly require bool.
    return type(value) is bool


@app.post("/terraform/plan")
def terraform_plan(request: dict[str, Any]):
    # ========================================================
    # 1. Request and nested-object schema
    # ========================================================

    required_top_level = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }

    if not required_top_level.issubset(request.keys()):
        return terraform_reject("INVALID_PLAN")

    if not valid_string(request["environment"]):
        return terraform_reject("INVALID_PLAN")

    if not valid_string(request["providerVersion"]):
        return terraform_reject("INVALID_PLAN")

    if not valid_bool(request["destroyApproved"]):
        return terraform_reject("INVALID_PLAN")

    if not isinstance(request["state"], dict):
        return terraform_reject("INVALID_PLAN")

    if not isinstance(request["resource"], dict):
        return terraform_reject("INVALID_PLAN")

    state = request["state"]
    resource = request["resource"]

    # State must have the shown fields and correct types.
    if "backend" not in state or "locked" not in state:
        return terraform_reject("INVALID_PLAN")

    if not valid_string(state["backend"]):
        return terraform_reject("INVALID_PLAN")

    if not valid_bool(state["locked"]):
        return terraform_reject("INVALID_PLAN")

    # Resource must have all shown fields.
    resource_required = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    }

    if not resource_required.issubset(resource.keys()):
        return terraform_reject("INVALID_PLAN")

    if not valid_string(resource["address"]):
        return terraform_reject("INVALID_PLAN")

    if not valid_string(resource["type"]):
        return terraform_reject("INVALID_PLAN")

    if not valid_string(resource["action"]):
        return terraform_reject("INVALID_PLAN")

    if not isinstance(resource["labels"], dict):
        return terraform_reject("INVALID_PLAN")

    if not valid_bool(resource["forceDestroy"]):
        return terraform_reject("INVALID_PLAN")

    # secret must be null or a string.
    if resource["secret"] is not None and not valid_string(resource["secret"]):
        return terraform_reject("INVALID_PLAN")

    # If supplied, secret must also be a valid action.
    if resource["action"] not in ALLOWED_ACTIONS:
        return terraform_reject("INVALID_PLAN")

    # Labels must have string keys and string values.
    for key, value in resource["labels"].items():
        if not isinstance(key, str) or not isinstance(value, str):
            return terraform_reject("INVALID_PLAN")

    # ========================================================
    # 2. Environment
    # ========================================================

    if request["environment"] != PRODUCTION_WORKSPACE:
        return terraform_reject("ENVIRONMENT_MISMATCH")

    # ========================================================
    # 3. Remote state
    # ========================================================

    if state["backend"] not in ALLOWED_BACKENDS:
        return terraform_reject("STATE_UNSAFE")

    if state["locked"] is not True:
        return terraform_reject("STATE_UNSAFE")

    # ========================================================
    # 4. Provider pinning
    # ========================================================

    provider = request["providerVersion"]

    if provider not in {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }:
        return terraform_reject("UNPINNED_PROVIDER")

    # ========================================================
    # 5. Required labels
    # ========================================================

    labels = resource["labels"]

    for key, expected_value in REQUIRED_LABELS.items():
        if labels.get(key) != expected_value:
            return terraform_reject("MISSING_LABELS")

    # ========================================================
    # 6. Secret
    # ========================================================

    secret = resource["secret"]

    if secret is not None:
        if not secret.startswith("secret://"):
            return terraform_reject("PLAINTEXT_SECRET")

        # Must contain something after secret://
        if len(secret) <= len("secret://"):
            return terraform_reject("PLAINTEXT_SECRET")

    # ========================================================
    # 7. Destructive delete approval
    # ========================================================

    if (
        resource["action"] == "delete"
        and resource["type"] in DESTRUCTIVE_RESOURCE_TYPES
    ):
        if request["destroyApproved"] is not True:
            return terraform_reject("DELETE_NOT_APPROVED")

    # ========================================================
    # 8. Production storage bucket forceDestroy
    # ========================================================

    if (
        request["environment"] == PRODUCTION_WORKSPACE
        and resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return terraform_reject("FORCE_DESTROY")

    return terraform_approve()