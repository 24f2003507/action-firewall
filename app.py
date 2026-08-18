import re
from typing import Any

from fastapi import FastAPI


app = FastAPI()


# ============================================================
# TASK 2 — LLM ACTION FIREWALL
# ============================================================

ASSIGNED_TENANT = "tenant-imbk5c0"
ALLOWED_EMAIL_DOMAIN = "notify-12r3kcs.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html",
}


def action_block(reason: str):
    return {
        "decision": "block",
        "reason": reason,
    }


def action_allow():
    return {
        "decision": "allow",
        "reason": "ALLOW",
    }


def is_unsafe_html(html: str) -> bool:
    lower = html.lower()

    # Block script elements
    if "<script" in lower:
        return True

    # Block iframe elements
    if "<iframe" in lower:
        return True

    # Block javascript: URLs
    if "javascript:" in lower:
        return True

    # Block inline event handlers such as onclick=, onload=,
    # onerror=, onmouseover=, etc.
    if re.search(r"\bon[a-z]+\s*=", lower):
        return True

    return False


@app.post("/action-firewall")
def action_firewall(request: dict[str, Any]):
    # --------------------------------------------------------
    # 1. Top-level schema
    # --------------------------------------------------------

    if not isinstance(request, dict):
        return action_block("INVALID_SCHEMA")

    required = {
        "provenance",
        "humanApproved",
        "action",
    }

    if not required.issubset(request.keys()):
        return action_block("INVALID_SCHEMA")

    if not isinstance(request["provenance"], str):
        return action_block("INVALID_SCHEMA")

    if request["provenance"] not in {"trusted", "untrusted"}:
        return action_block("INVALID_SCHEMA")

    if type(request["humanApproved"]) is not bool:
        return action_block("INVALID_SCHEMA")

    if "untrustedContent" in request:
        if (
            request["untrustedContent"] is not None
            and not isinstance(request["untrustedContent"], str)
        ):
            return action_block("INVALID_SCHEMA")

    if not isinstance(request["action"], dict):
        return action_block("INVALID_SCHEMA")

    action = request["action"]

    if "tool" not in action or "args" not in action:
        return action_block("INVALID_SCHEMA")

    if not isinstance(action["tool"], str):
        return action_block("INVALID_SCHEMA")

    if not isinstance(action["args"], dict):
        return action_block("INVALID_SCHEMA")

    # --------------------------------------------------------
    # 2. Tool allowlist
    # --------------------------------------------------------

    tool = action["tool"]

    if tool not in ALLOWED_TOOLS:
        return action_block("TOOL_NOT_ALLOWED")

    args = action["args"]

    # --------------------------------------------------------
    # 3. Selected tool argument schema
    # --------------------------------------------------------

    if tool == "search":

        if set(args.keys()) != {"query"}:
            return action_block("INVALID_SCHEMA")

        if not isinstance(args["query"], str):
            return action_block("INVALID_SCHEMA")

        if not 1 <= len(args["query"]) <= 200:
            return action_block("INVALID_SCHEMA")

    elif tool == "lookup_record":

        if set(args.keys()) != {"tenantId", "recordId"}:
            return action_block("INVALID_SCHEMA")

        if not isinstance(args["tenantId"], str):
            return action_block("INVALID_SCHEMA")

        if not isinstance(args["recordId"], str):
            return action_block("INVALID_SCHEMA")

        if args["recordId"] == "":
            return action_block("INVALID_SCHEMA")

    elif tool == "send_email":

        if set(args.keys()) != {"to", "subject", "body"}:
            return action_block("INVALID_SCHEMA")

        if not isinstance(args["to"], str):
            return action_block("INVALID_SCHEMA")

        if not isinstance(args["subject"], str):
            return action_block("INVALID_SCHEMA")

        if not isinstance(args["body"], str):
            return action_block("INVALID_SCHEMA")

    elif tool == "render_html":

        if set(args.keys()) != {"html"}:
            return action_block("INVALID_SCHEMA")

        if not isinstance(args["html"], str):
            return action_block("INVALID_SCHEMA")

    # --------------------------------------------------------
    # 4. Tenant scope
    # --------------------------------------------------------

    if tool == "lookup_record":

        if args["tenantId"] != ASSIGNED_TENANT:
            return action_block("TENANT_SCOPE")

    # --------------------------------------------------------
    # 5. Exact email-domain egress
    # --------------------------------------------------------

    if tool == "send_email":

        recipient = args["to"]

        if "@" not in recipient:
            return action_block("EGRESS_DENIED")

        local_part, domain = recipient.rsplit("@", 1)

        if not local_part:
            return action_block("EGRESS_DENIED")

        if domain != ALLOWED_EMAIL_DOMAIN:
            return action_block("EGRESS_DENIED")

    # --------------------------------------------------------
    # 6. Human approval
    # --------------------------------------------------------

    if tool == "send_email":

        if request["humanApproved"] is not True:
            return action_block("APPROVAL_REQUIRED")

    # --------------------------------------------------------
    # 7. HTML safety
    # --------------------------------------------------------

    if tool == "render_html":

        if is_unsafe_html(args["html"]):
            return action_block("UNSAFE_OUTPUT")

    # --------------------------------------------------------
    # All checks passed
    # --------------------------------------------------------

    return action_allow()


# ============================================================
# TASK 3 — TERRAFORM PLAN POLICY GATE
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

ALLOWED_ACTIONS = {
    "create",
    "update",
    "delete",
}

DESTRUCTIVE_RESOURCE_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
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


@app.post("/terraform/plan")
def terraform_plan(request: dict[str, Any]):
    # --------------------------------------------------------
    # 1. Request and nested-object types/schema
    # --------------------------------------------------------

    if not isinstance(request, dict):
        return terraform_reject("INVALID_PLAN")

    required_top_level = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }

    if not required_top_level.issubset(request.keys()):
        return terraform_reject("INVALID_PLAN")

    if not isinstance(request["environment"], str):
        return terraform_reject("INVALID_PLAN")

    if not isinstance(request["state"], dict):
        return terraform_reject("INVALID_PLAN")

    if not isinstance(request["providerVersion"], str):
        return terraform_reject("INVALID_PLAN")

    if type(request["destroyApproved"]) is not bool:
        return terraform_reject("INVALID_PLAN")

    if not isinstance(request["resource"], dict):
        return terraform_reject("INVALID_PLAN")

    state = request["state"]
    resource = request["resource"]

    # State schema
    if "backend" not in state:
        return terraform_reject("INVALID_PLAN")

    if "locked" not in state:
        return terraform_reject("INVALID_PLAN")

    if not isinstance(state["backend"], str):
        return terraform_reject("INVALID_PLAN")

    if type(state["locked"]) is not bool:
        return terraform_reject("INVALID_PLAN")

    # Resource schema
    required_resource = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    }

    if not required_resource.issubset(resource.keys()):
        return terraform_reject("INVALID_PLAN")

    if not isinstance(resource["address"], str):
        return terraform_reject("INVALID_PLAN")

    if not isinstance(resource["type"], str):
        return terraform_reject("INVALID_PLAN")

    if not isinstance(resource["action"], str):
        return terraform_reject("INVALID_PLAN")

    if not isinstance(resource["labels"], dict):
        return terraform_reject("INVALID_PLAN")

    if resource["secret"] is not None:
        if not isinstance(resource["secret"], str):
            return terraform_reject("INVALID_PLAN")

    if type(resource["forceDestroy"]) is not bool:
        return terraform_reject("INVALID_PLAN")

    if resource["action"] not in ALLOWED_ACTIONS:
        return terraform_reject("INVALID_PLAN")

    # --------------------------------------------------------
    # 2. Environment
    # --------------------------------------------------------

    if request["environment"] != PRODUCTION_WORKSPACE:
        return terraform_reject("ENVIRONMENT_MISMATCH")

    # --------------------------------------------------------
    # 3. Remote state
    # --------------------------------------------------------

    if state["backend"] not in ALLOWED_BACKENDS:
        return terraform_reject("STATE_UNSAFE")

    if state["locked"] is not True:
        return terraform_reject("STATE_UNSAFE")

    # --------------------------------------------------------
    # 4. Provider pinning
    # --------------------------------------------------------

    provider_version = request["providerVersion"]

    if provider_version not in {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }:
        return terraform_reject("UNPINNED_PROVIDER")

    # --------------------------------------------------------
    # 5. Required labels
    # --------------------------------------------------------

    labels = resource["labels"]

    for key, expected_value in REQUIRED_LABELS.items():

        if key not in labels:
            return terraform_reject("MISSING_LABELS")

        if labels[key] != expected_value:
            return terraform_reject("MISSING_LABELS")

    # --------------------------------------------------------
    # 6. Secret
    # --------------------------------------------------------

    secret = resource["secret"]

    if secret is not None:

        if not secret.startswith("secret://"):
            return terraform_reject("PLAINTEXT_SECRET")

        if len(secret) <= len("secret://"):
            return terraform_reject("PLAINTEXT_SECRET")

    # --------------------------------------------------------
    # 7. Destructive deletes
    # --------------------------------------------------------

    if resource["action"] == "delete":

        if resource["type"] in DESTRUCTIVE_RESOURCE_TYPES:

            if request["destroyApproved"] is not True:
                return terraform_reject("DELETE_NOT_APPROVED")

    # --------------------------------------------------------
    # 8. Production storage bucket forceDestroy
    # --------------------------------------------------------

    if resource["type"] == "storage_bucket":

        if resource["forceDestroy"] is True:

            if request["environment"] == PRODUCTION_WORKSPACE:
                return terraform_reject("FORCE_DESTROY")

    # --------------------------------------------------------
    # All checks passed
    # --------------------------------------------------------

    return terraform_approve()


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "TDS GA7",
    }