import json
import re
from typing import Any
from urllib.parse import unquote, urlparse

from fastapi import FastAPI, Request


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


def is_unsafe_html(html_text: str) -> bool:
    lower = html_text.lower()

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
async def action_firewall(request: Request):
    try:
        data = await request.json()
    except Exception:
        return action_block("INVALID_SCHEMA")

    if not isinstance(data, dict):
        return action_block("INVALID_SCHEMA")

    required = {
        "provenance",
        "humanApproved",
        "action",
    }

    if not required.issubset(data.keys()):
        return action_block("INVALID_SCHEMA")

    if not isinstance(data["provenance"], str):
        return action_block("INVALID_SCHEMA")

    if data["provenance"] not in {"trusted", "untrusted"}:
        return action_block("INVALID_SCHEMA")

    if type(data["humanApproved"]) is not bool:
        return action_block("INVALID_SCHEMA")

    if "untrustedContent" in data:
        if (
            data["untrustedContent"] is not None
            and not isinstance(data["untrustedContent"], str)
        ):
            return action_block("INVALID_SCHEMA")

    if not isinstance(data["action"], dict):
        return action_block("INVALID_SCHEMA")

    action = data["action"]

    if "tool" not in action or "args" not in action:
        return action_block("INVALID_SCHEMA")

    if not isinstance(action["tool"], str):
        return action_block("INVALID_SCHEMA")

    if not isinstance(action["args"], dict):
        return action_block("INVALID_SCHEMA")

    tool = action["tool"]

    if tool not in ALLOWED_TOOLS:
        return action_block("TOOL_NOT_ALLOWED")

    args = action["args"]

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

    if tool == "lookup_record":

        if args["tenantId"] != ASSIGNED_TENANT:
            return action_block("TENANT_SCOPE")

    if tool == "send_email":

        recipient = args["to"]

        if "@" not in recipient:
            return action_block("EGRESS_DENIED")

        local_part, domain = recipient.rsplit("@", 1)

        if not local_part:
            return action_block("EGRESS_DENIED")

        if domain != ALLOWED_EMAIL_DOMAIN:
            return action_block("EGRESS_DENIED")

        if data["humanApproved"] is not True:
            return action_block("APPROVAL_REQUIRED")

    if tool == "render_html":

        if is_unsafe_html(args["html"]):
            return action_block("UNSAFE_OUTPUT")

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
async def terraform_plan(request: Request):
    try:
        data = await request.json()
    except Exception:
        return terraform_reject("INVALID_PLAN")

    if not isinstance(data, dict):
        return terraform_reject("INVALID_PLAN")

    required_top_level = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }

    if not required_top_level.issubset(data.keys()):
        return terraform_reject("INVALID_PLAN")

    if not isinstance(data["environment"], str):
        return terraform_reject("INVALID_PLAN")

    if not isinstance(data["state"], dict):
        return terraform_reject("INVALID_PLAN")

    if not isinstance(data["providerVersion"], str):
        return terraform_reject("INVALID_PLAN")

    if type(data["destroyApproved"]) is not bool:
        return terraform_reject("INVALID_PLAN")

    if not isinstance(data["resource"], dict):
        return terraform_reject("INVALID_PLAN")

    state = data["state"]
    resource = data["resource"]

    if "backend" not in state or "locked" not in state:
        return terraform_reject("INVALID_PLAN")

    if not isinstance(state["backend"], str):
        return terraform_reject("INVALID_PLAN")

    if type(state["locked"]) is not bool:
        return terraform_reject("INVALID_PLAN")

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

    if data["environment"] != PRODUCTION_WORKSPACE:
        return terraform_reject("ENVIRONMENT_MISMATCH")

    if state["backend"] not in ALLOWED_BACKENDS:
        return terraform_reject("STATE_UNSAFE")

    if state["locked"] is not True:
        return terraform_reject("STATE_UNSAFE")

    if data["providerVersion"] not in {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }:
        return terraform_reject("UNPINNED_PROVIDER")

    labels = resource["labels"]

    for key, expected_value in REQUIRED_LABELS.items():

        if key not in labels:
            return terraform_reject("MISSING_LABELS")

        if labels[key] != expected_value:
            return terraform_reject("MISSING_LABELS")

    secret = resource["secret"]

    if secret is not None:

        if not secret.startswith("secret://"):
            return terraform_reject("PLAINTEXT_SECRET")

        if len(secret) <= len("secret://"):
            return terraform_reject("PLAINTEXT_SECRET")

    if resource["action"] == "delete":

        if resource["type"] in DESTRUCTIVE_RESOURCE_TYPES:

            if data["destroyApproved"] is not True:
                return terraform_reject("DELETE_NOT_APPROVED")

    if (
        data["environment"] == PRODUCTION_WORKSPACE
        and resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return terraform_reject("FORCE_DESTROY")

    return terraform_approve()


# ============================================================
# TASK 4 — LLM OUTPUT HANDLING GATE
# ============================================================

ALLOWED_EXTERNAL_HOSTS = {
    "cdn-rseko8l.example",
    "app-l8xc0jl.example",
}

OUTPUT_CHANNELS = {
    "html",
    "markdown",
    "url",
    "sql",
    "shell",
}


def output_safe():
    return {
        "safe": True,
        "reason": "SAFE",
    }


def output_unsafe(reason: str):
    return {
        "safe": False,
        "reason": reason,
    }


# ============================================================
# Decode exactly once
#
# Order:
# 1. Percent escapes
# 2. HTML entities
# 3. \uXXXX escapes
# ============================================================

def decode_once(value: str) -> str:

    decoded = unquote(value)

    decoded = re.sub(
        r"&#([0-9]+);",
        lambda match: (
            chr(int(match.group(1)))
            if int(match.group(1)) <= 0x10FFFF
            else match.group(0)
        ),
        decoded,
    )

    decoded = re.sub(
        r"&#x([0-9a-fA-F]+);",
        lambda match: (
            chr(int(match.group(1), 16))
            if int(match.group(1), 16) <= 0x10FFFF
            else match.group(0)
        ),
        decoded,
    )

    entity_map = {
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&apos;": "'",
        "&amp;": "&",
    }

    for entity, replacement in entity_map.items():
        decoded = decoded.replace(entity, replacement)

    decoded = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda match: chr(int(match.group(1), 16)),
        decoded,
    )

    return decoded


# ============================================================
# Dangerous schemes
# ============================================================

DANGEROUS_SCHEME_PATTERN = re.compile(
    r"(?:javascript|data|vbscript)\s*:",
    re.IGNORECASE,
)


def contains_dangerous_scheme(text: str) -> bool:
    return DANGEROUS_SCHEME_PATTERN.search(text) is not None


# ============================================================
# URL extraction
# ============================================================

def extract_urls(channel: str, text: str) -> list[str]:

    urls = []

    if channel == "html":

        pattern = re.compile(
            r"""(?:src|href)\s*=\s*(["'])(.*?)\1""",
            re.IGNORECASE | re.DOTALL,
        )

        for match in pattern.finditer(text):
            urls.append(match.group(2))

    elif channel == "markdown":

        pattern = re.compile(
            r"\]\(\s*([^)]+?)\s*\)",
            re.DOTALL,
        )

        for match in pattern.finditer(text):

            target = match.group(1).strip()

            if (
                len(target) >= 2
                and target[0] == "<"
                and target[-1] == ">"
            ):
                target = target[1:-1]

            title_match = re.match(
                r"""(\S+)(?:\s+["'].*["'])?$""",
                target,
                re.DOTALL,
            )

            if title_match:
                target = title_match.group(1)

            urls.append(target)

    elif channel == "url":

        urls.append(text.strip())

    return urls


# ============================================================
# URL scheme validation
# ============================================================

def url_has_dangerous_scheme(url: str) -> bool:

    stripped = url.strip()

    if contains_dangerous_scheme(stripped):
        return True

    parse_target = stripped

    if stripped.startswith("//"):
        parse_target = "https:" + stripped

    parsed = urlparse(parse_target)

    if parsed.scheme:

        if parsed.scheme.lower() not in {
            "http",
            "https",
        }:
            return True

    return False


# ============================================================
# External URL validation
# ============================================================

def url_is_external(url: str) -> bool:

    stripped = url.strip()

    if stripped.startswith("//"):

        parsed = urlparse(
            "https:" + stripped
        )

    elif stripped.startswith("/"):

        return False

    else:

        parsed = urlparse(stripped)

    hostname = parsed.hostname

    if hostname is None:
        return False

    return hostname.lower() not in ALLOWED_EXTERNAL_HOSTS


# ============================================================
# HTML checks
# ============================================================

SCRIPT_TAG_PATTERN = re.compile(
    r"<\s*(?:script|iframe|object|embed)\b",
    re.IGNORECASE,
)

EVENT_HANDLER_PATTERN = re.compile(
    r"\bon[a-z]+\s*=",
    re.IGNORECASE,
)


# ============================================================
# SQL checks
# ============================================================

def contains_sql_metachar(text: str) -> bool:

    if "'" in text:
        return True

    if '"' in text:
        return True

    if ";" in text:
        return True

    if "--" in text:
        return True

    if "/*" in text:
        return True

    if re.search(
        r"\bunion\b",
        text,
        re.IGNORECASE,
    ):
        return True

    if re.search(
        r"\bor\s+1\s*=\s*1\b",
        text,
        re.IGNORECASE,
    ):
        return True

    return False


# ============================================================
# Shell checks
# ============================================================

def contains_shell_metachar(text: str) -> bool:

    if any(
        character in text
        for character in ";&|`<>"
    ):
        return True

    if "$(" in text:
        return True

    if "${" in text:
        return True

    return False


# ============================================================
# Channel checks
# ============================================================

def check_channel(
    channel: str,
    text: str,
) -> str | None:

    if channel == "html":

        # 1. SCRIPT_TAG
        if SCRIPT_TAG_PATTERN.search(text):
            return "SCRIPT_TAG"

        # 2. EVENT_HANDLER
        if EVENT_HANDLER_PATTERN.search(text):
            return "EVENT_HANDLER"

        # 3. DANGEROUS_SCHEME
        if contains_dangerous_scheme(text):
            return "DANGEROUS_SCHEME"

        # 4. EXTERNAL_EXFIL
        urls = extract_urls(
            "html",
            text,
        )

        for url in urls:

            if url_has_dangerous_scheme(url):
                return "DANGEROUS_SCHEME"

            if url_is_external(url):
                return "EXTERNAL_EXFIL"

        return None

    if channel == "markdown":

        # 1. DANGEROUS_SCHEME
        if contains_dangerous_scheme(text):
            return "DANGEROUS_SCHEME"

        # 2. EXTERNAL_EXFIL
        urls = extract_urls(
            "markdown",
            text,
        )

        for url in urls:

            if url_has_dangerous_scheme(url):
                return "DANGEROUS_SCHEME"

            if url_is_external(url):
                return "EXTERNAL_EXFIL"

        return None

    if channel == "url":

        # 1. DANGEROUS_SCHEME
        if contains_dangerous_scheme(text):
            return "DANGEROUS_SCHEME"

        # 2. EXTERNAL_EXFIL
        urls = extract_urls(
            "url",
            text,
        )

        for url in urls:

            if url_has_dangerous_scheme(url):
                return "DANGEROUS_SCHEME"

            if url_is_external(url):
                return "EXTERNAL_EXFIL"

        return None

    if channel == "sql":

        if contains_sql_metachar(text):
            return "SQL_METACHAR"

        return None

    if channel == "shell":

        if contains_shell_metachar(text):
            return "SHELL_METACHAR"

        return None

    return "INVALID_SCHEMA"


# ============================================================
# /sanitize-output
# ============================================================

@app.post("/sanitize-output")
async def sanitize_output(request: Request):

    # Read the raw JSON ourselves so that even invalid JSON
    # shapes can receive a 2xx JSON response.

    try:
        raw_body = await request.body()
        data = json.loads(raw_body)
    except Exception:
        return output_unsafe("INVALID_SCHEMA")

    # --------------------------------------------------------
    # RULE 1 — INVALID_SCHEMA
    # --------------------------------------------------------

    if not isinstance(data, dict):
        return output_unsafe("INVALID_SCHEMA")

    if "channel" not in data:
        return output_unsafe("INVALID_SCHEMA")

    if "output" not in data:
        return output_unsafe("INVALID_SCHEMA")

    channel = data["channel"]
    output = data["output"]

    if channel not in OUTPUT_CHANNELS:
        return output_unsafe("INVALID_SCHEMA")

    if not isinstance(output, str):
        return output_unsafe("INVALID_SCHEMA")

    if len(output) > 20000:
        return output_unsafe("INVALID_SCHEMA")

    # --------------------------------------------------------
    # RULE 2 — ENCODED_PAYLOAD
    # --------------------------------------------------------

    decoded = decode_once(output)

    if decoded != output:

        decoded_reason = check_channel(
            channel,
            decoded,
        )

        if decoded_reason is not None:
            return output_unsafe(
                "ENCODED_PAYLOAD"
            )

    # --------------------------------------------------------
    # RULE 3 — Original output
    # --------------------------------------------------------

    reason = check_channel(
        channel,
        output,
    )

    if reason is not None:
        return output_unsafe(reason)

    return output_safe()


# ============================================================
# ROOT HEALTH CHECK
# ============================================================

@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "TDS GA7",
    }