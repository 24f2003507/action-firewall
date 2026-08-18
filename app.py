import html
import re
from typing import Any
from urllib.parse import unquote, urlparse

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
def action_firewall(request: dict[str, Any]):
    # 1. Top-level schema

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

    # 2. Tool allowlist

    tool = action["tool"]

    if tool not in ALLOWED_TOOLS:
        return action_block("TOOL_NOT_ALLOWED")

    args = action["args"]

    # 3. Selected tool argument schema

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

    # 4. Tenant scope

    if tool == "lookup_record":

        if args["tenantId"] != ASSIGNED_TENANT:
            return action_block("TENANT_SCOPE")

    # 5. Exact email-domain egress

    if tool == "send_email":

        recipient = args["to"]

        if "@" not in recipient:
            return action_block("EGRESS_DENIED")

        local_part, domain = recipient.rsplit("@", 1)

        if not local_part:
            return action_block("EGRESS_DENIED")

        if domain != ALLOWED_EMAIL_DOMAIN:
            return action_block("EGRESS_DENIED")

    # 6. Human approval

    if tool == "send_email":

        if request["humanApproved"] is not True:
            return action_block("APPROVAL_REQUIRED")

    # 7. HTML safety

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
def terraform_plan(request: dict[str, Any]):
    # 1. Request and nested-object types/schema

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

    if "backend" not in state:
        return terraform_reject("INVALID_PLAN")

    if "locked" not in state:
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

    # 2. Environment

    if request["environment"] != PRODUCTION_WORKSPACE:
        return terraform_reject("ENVIRONMENT_MISMATCH")

    # 3. State

    if state["backend"] not in ALLOWED_BACKENDS:
        return terraform_reject("STATE_UNSAFE")

    if state["locked"] is not True:
        return terraform_reject("STATE_UNSAFE")

    # 4. Provider pinning

    if request["providerVersion"] not in {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }:
        return terraform_reject("UNPINNED_PROVIDER")

    # 5. Required labels

    labels = resource["labels"]

    for key, expected_value in REQUIRED_LABELS.items():

        if key not in labels:
            return terraform_reject("MISSING_LABELS")

        if labels[key] != expected_value:
            return terraform_reject("MISSING_LABELS")

    # 6. Secret

    secret = resource["secret"]

    if secret is not None:

        if not secret.startswith("secret://"):
            return terraform_reject("PLAINTEXT_SECRET")

        if len(secret) <= len("secret://"):
            return terraform_reject("PLAINTEXT_SECRET")

    # 7. Destructive deletes

    if resource["action"] == "delete":

        if resource["type"] in DESTRUCTIVE_RESOURCE_TYPES:

            if request["destroyApproved"] is not True:
                return terraform_reject("DELETE_NOT_APPROVED")

    # 8. Force destroy

    if (
        request["environment"] == PRODUCTION_WORKSPACE
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


# ------------------------------------------------------------
# Output response helpers
# ------------------------------------------------------------

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


# ------------------------------------------------------------
# Decode exactly once:
#
# 1. Percent escapes
# 2. HTML numeric/named entities
# 3. \uXXXX escapes
# ------------------------------------------------------------

def decode_once(value: str) -> str:
    decoded = unquote(value)

    # Decode only the entities explicitly required by the task.
    entity_map = {
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&apos;": "'",
        "&amp;": "&",
    }

    # Numeric decimal entities: &#NN;
    decoded = re.sub(
        r"&#([0-9]+);",
        lambda match: chr(int(match.group(1)))
        if int(match.group(1)) <= 0x10FFFF
        else match.group(0),
        decoded,
    )

    # Numeric hexadecimal entities: &#xNN;
    decoded = re.sub(
        r"&#x([0-9a-fA-F]+);",
        lambda match: chr(int(match.group(1), 16))
        if int(match.group(1), 16) <= 0x10FFFF
        else match.group(0),
        decoded,
    )

    for entity, replacement in entity_map.items():
        decoded = decoded.replace(entity, replacement)

    # Decode literal \uXXXX escapes exactly once.
    decoded = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda match: chr(int(match.group(1), 16)),
        decoded,
    )

    return decoded


# ------------------------------------------------------------
# Dangerous scheme detection
# ------------------------------------------------------------

DANGEROUS_SCHEME_PATTERN = re.compile(
    r"(?:javascript|data|vbscript)\s*:",
    re.IGNORECASE,
)


def contains_dangerous_scheme(text: str) -> bool:
    return DANGEROUS_SCHEME_PATTERN.search(text) is not None


# ------------------------------------------------------------
# URL extraction
# ------------------------------------------------------------

def extract_urls(channel: str, text: str) -> list[str]:
    urls = []

    if channel == "html":
        # Only quoted src= and href= attributes.
        pattern = re.compile(
            r"""(?:src|href)\s*=\s*(["'])(.*?)\1""",
            re.IGNORECASE | re.DOTALL,
        )

        for match in pattern.finditer(text):
            urls.append(match.group(2))

    elif channel == "markdown":
        # Extract the target inside ](...).
        pattern = re.compile(
            r"\]\(\s*([^)]+?)\s*\)",
            re.DOTALL,
        )

        for match in pattern.finditer(text):
            target = match.group(1).strip()

            # Markdown allows angle brackets around URLs.
            if len(target) >= 2 and target[0] == "<" and target[-1] == ">":
                target = target[1:-1]

            # Ignore optional markdown title after the URL.
            # The common forms are:
            # ](https://host/path "title")
            # ](https://host/path 'title')
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


# ------------------------------------------------------------
# URL scheme validation
# ------------------------------------------------------------

def url_has_dangerous_or_invalid_scheme(url: str) -> bool:
    stripped = url.strip()

    # Explicit dangerous schemes.
    if contains_dangerous_scheme(stripped):
        return True

    # Protocol-relative URLs are treated as HTTPS.
    parse_target = stripped

    if stripped.startswith("//"):
        parse_target = "https:" + stripped

    parsed = urlparse(parse_target)

    # A URL with an explicit scheme must be HTTP or HTTPS.
    if parsed.scheme:
        if parsed.scheme.lower() not in {"http", "https"}:
            return True

    return False


# ------------------------------------------------------------
# External-host validation
# ------------------------------------------------------------

def url_is_external(url: str) -> bool:
    stripped = url.strip()

    # Relative URLs are allowed.
    if stripped.startswith("/"):
        # Important distinction:
        # //host/path is protocol-relative and therefore absolute.
        if stripped.startswith("//"):
            parsed = urlparse("https:" + stripped)
        else:
            return False
    else:
        parsed = urlparse(stripped)

    # No hostname means it is a relative reference.
    hostname = parsed.hostname

    if hostname is None:
        return False

    # Exact hostname match only.
    return hostname.lower() not in ALLOWED_EXTERNAL_HOSTS


# ------------------------------------------------------------
# HTML checks
# ------------------------------------------------------------

SCRIPT_TAG_PATTERN = re.compile(
    r"<\s*(?:script|iframe|object|embed)\b",
    re.IGNORECASE,
)

EVENT_HANDLER_PATTERN = re.compile(
    r"\bon[a-z]+\s*=",
    re.IGNORECASE,
)


# ------------------------------------------------------------
# SQL checks
# ------------------------------------------------------------

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

    if re.search(r"\bunion\b", text, re.IGNORECASE):
        return True

    if re.search(r"\bor\s+1\s*=\s*1\b", text, re.IGNORECASE):
        return True

    return False


# ------------------------------------------------------------
# Shell checks
# ------------------------------------------------------------

def contains_shell_metachar(text: str) -> bool:
    if any(character in text for character in ";&|`<>"):
        return True

    if "$(" in text:
        return True

    if "${" in text:
        return True

    return False


# ------------------------------------------------------------
# Apply channel rules to a string.
#
# IMPORTANT:
# This function does NOT perform encoded-payload checking.
# The caller handles that separately so decoding happens once.
# ------------------------------------------------------------

def check_channel(channel: str, text: str) -> str | None:

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
        urls = extract_urls("html", text)

        for url in urls:

            if url_has_dangerous_or_invalid_scheme(url):
                return "DANGEROUS_SCHEME"

            if url_is_external(url):
                return "EXTERNAL_EXFIL"

        return None

    if channel == "markdown":

        # 1. DANGEROUS_SCHEME
        if contains_dangerous_scheme(text):
            return "DANGEROUS_SCHEME"

        # 2. EXTERNAL_EXFIL
        urls = extract_urls("markdown", text)

        for url in urls:

            if url_has_dangerous_or_invalid_scheme(url):
                return "DANGEROUS_SCHEME"

            if url_is_external(url):
                return "EXTERNAL_EXFIL"

        return None

    if channel == "url":

        # 1. DANGEROUS_SCHEME
        if contains_dangerous_scheme(text):
            return "DANGEROUS_SCHEME"

        # 2. EXTERNAL_EXFIL
        urls = extract_urls("url", text)

        for url in urls:

            if url_has_dangerous_or_invalid_scheme(url):
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


# ------------------------------------------------------------
# /sanitize-output
# ------------------------------------------------------------

@app.post("/sanitize-output")
def sanitize_output(request: Any):

    # ========================================================
    # RULE 1 — INVALID_SCHEMA
    # ========================================================

    if not isinstance(request, dict):
        return output_unsafe("INVALID_SCHEMA")

    if "channel" not in request:
        return output_unsafe("INVALID_SCHEMA")

    if "output" not in request:
        return output_unsafe("INVALID_SCHEMA")

    channel = request["channel"]
    output = request["output"]

    if channel not in OUTPUT_CHANNELS:
        return output_unsafe("INVALID_SCHEMA")

    if not isinstance(output, str):
        return output_unsafe("INVALID_SCHEMA")

    if len(output) > 20000:
        return output_unsafe("INVALID_SCHEMA")

    # ========================================================
    # RULE 2 — ENCODED_PAYLOAD
    #
    # Decode exactly once. If the decoded version differs
    # from the original AND the decoded version would trigger
    # any channel rule, return ENCODED_PAYLOAD.
    # ========================================================

    decoded = decode_once(output)

    if decoded != output:

        decoded_reason = check_channel(channel, decoded)

        if decoded_reason is not None:
            return output_unsafe("ENCODED_PAYLOAD")

    # ========================================================
    # RULE 3 — Apply channel rules to ORIGINAL output
    # ========================================================

    reason = check_channel(channel, output)

    if reason is not None:
        return output_unsafe(reason)

    # ========================================================
    # Everything passed
    # ========================================================

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