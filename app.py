from urllib.parse import urlparse

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI()

ASSIGNED_TENANT = "tenant-imbk5c0"
ALLOWED_EMAIL_DOMAIN = "notify-12r3kcs.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html",
}


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    args: dict


class FirewallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provenance: str
    humanApproved: bool
    untrustedContent: str | None = None
    action: Action


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

    # Inline event handlers such as onclick=, onload=, onerror=, etc.
    import re

    if re.search(r"\bon[a-z]+\s*=", lower):
        return True

    return False


@app.post("/action-firewall")
def action_firewall(request: FirewallRequest):
    # 1. Top-level schema
    if request.provenance not in {"trusted", "untrusted"}:
        return block("INVALID_SCHEMA")

    if not isinstance(request.humanApproved, bool):
        return block("INVALID_SCHEMA")

    action = request.action

    if not isinstance(action.tool, str) or not isinstance(action.args, dict):
        return block("INVALID_SCHEMA")

    # 2. Tool allowlist
    if action.tool not in ALLOWED_TOOLS:
        return block("TOOL_NOT_ALLOWED")

    args = action.args

    # 3. Selected tool argument schema
    if action.tool == "search":
        if set(args.keys()) != {"query"}:
            return block("INVALID_SCHEMA")

        query = args["query"]

        if not isinstance(query, str):
            return block("INVALID_SCHEMA")

        if not (1 <= len(query) <= 200):
            return block("INVALID_SCHEMA")

    elif action.tool == "lookup_record":
        if set(args.keys()) != {"tenantId", "recordId"}:
            return block("INVALID_SCHEMA")

        if not isinstance(args["tenantId"], str):
            return block("INVALID_SCHEMA")

        if not isinstance(args["recordId"], str):
            return block("INVALID_SCHEMA")

        if args["recordId"] == "":
            return block("INVALID_SCHEMA")

    elif action.tool == "send_email":
        if set(args.keys()) != {"to", "subject", "body"}:
            return block("INVALID_SCHEMA")

        if not isinstance(args["to"], str):
            return block("INVALID_SCHEMA")

        if not isinstance(args["subject"], str):
            return block("INVALID_SCHEMA")

        if not isinstance(args["body"], str):
            return block("INVALID_SCHEMA")

    elif action.tool == "render_html":
        if set(args.keys()) != {"html"}:
            return block("INVALID_SCHEMA")

        if not isinstance(args["html"], str):
            return block("INVALID_SCHEMA")

    # 4. Tenant scope
    if action.tool == "lookup_record":
        if args["tenantId"] != ASSIGNED_TENANT:
            return block("TENANT_SCOPE")

    # 5. Egress restrictions
    if action.tool == "send_email":
        recipient = args["to"]

        if "@" not in recipient:
            return block("EGRESS_DENIED")

        local, domain = recipient.rsplit("@", 1)

        if not local or domain != ALLOWED_EMAIL_DOMAIN:
            return block("EGRESS_DENIED")

    # 6. Approval
    if action.tool == "send_email":
        if request.humanApproved is not True:
            return block("APPROVAL_REQUIRED")

    # 7. HTML safety
    if action.tool == "render_html":
        if is_unsafe_html(args["html"]):
            return block("UNSAFE_OUTPUT")

    return allow()