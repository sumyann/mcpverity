"""Parse MCP server source and manifest files into a scan context.

Recognises three kinds of files:
  - manifest.json / mcp.json / server.json -- MCP server manifests
  - any *.json file with top-level `mcpServers` key -- client-side launch
    config (Claude Desktop, Cursor, Continue.dev, .mcp.json, etc.)
  - everything else -- treated as code files (regex + string search)
"""
import json
import re
from typing import Any

MANIFEST_NAMES = {"mcp.json", "manifest.json", "server.json", "mcp-manifest.json", ".mcp.json"}


def _mcpservers_to_synthetic_manifest(data: dict, path: str, raw: str) -> dict:
    """Convert a `mcpServers` block into a manifest-shaped dict so the existing
    rule engine sees every listed launcher as a tool with permission scope.

    Given:
        {"mcpServers": {"blender": {"command": "uvx", "args": ["blender-mcp"], "env": {...}}}}

    Emits:
        {
          "_path": path, "_raw": raw, "_kind": "mcpServers",
          "tools": [{"name": "blender", "command": "uvx", "args": [...], "env": {...},
                     "description": "Launches via uvx: blender-mcp"}],
          "servers": [ ...same list, kept for the launcher-config rule... ]
        }
    """
    servers = []
    tools_shape = []
    mcp_servers_obj = data.get("mcpServers") or {}
    if not isinstance(mcp_servers_obj, dict):
        mcp_servers_obj = {}
    for name, cfg in mcp_servers_obj.items():
        if not isinstance(cfg, dict):
            continue
        entry = {
            "name": name,
            "command": cfg.get("command", ""),
            "args": cfg.get("args", []) if isinstance(cfg.get("args"), list) else [],
            "env": cfg.get("env", {}) if isinstance(cfg.get("env"), dict) else {},
            "url": cfg.get("url"),
            "type": cfg.get("type"),  # "stdio" | "sse" | "http"
        }
        servers.append(entry)
        # Mirror into a synthetic tool so W001/W003 rules can inspect fields.
        tools_shape.append({
            "name": name,
            "description": f"Launches via {entry['command']}: {' '.join(str(a) for a in entry['args'])}",
            "command": entry["command"],
            "args": entry["args"],
            "env": entry["env"],
            "url": entry["url"],
        })
    return {
        "_path": path,
        "_raw": raw,
        "_kind": "mcpServers",
        "tools": tools_shape,
        "servers": servers,
    }


def parse_files(files: list[dict]) -> dict[str, Any]:
    """Split files into code files, MCP manifests, and mcpServers launch configs."""
    code_files: list[dict] = []
    manifests: list[dict] = []

    for f in files:
        path = f["path"]
        content = f["content"]
        name = path.split("/")[-1].lower()

        # Try to parse any .json file. Route to the right bucket based on shape.
        parsed = None
        if content.strip().startswith("{"):
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError:
                parsed = None

        if isinstance(parsed, dict) and "mcpServers" in parsed:
            manifests.append(_mcpservers_to_synthetic_manifest(parsed, path, content))
            continue

        if name in MANIFEST_NAMES or name.endswith(".mcp.json"):
            if isinstance(parsed, dict):
                parsed["_path"] = path
                parsed["_raw"] = content
                parsed["_kind"] = "manifest"
                if "tools" not in parsed and "actions" in parsed:
                    parsed["tools"] = parsed["actions"]
                manifests.append(parsed)
                continue

        code_files.append({"path": path, "content": content})

    return {"files": code_files, "manifests": manifests}


def extract_tool_descriptions(context: dict[str, Any]) -> list[dict[str, str]]:
    """Pull out every tool description (from manifest + source) for optional LLM check."""
    out: list[dict[str, str]] = []
    for m in context["manifests"]:
        for tool in m.get("tools", []) or []:
            desc = tool.get("description") or tool.get("prompt") or ""
            if desc:
                out.append({
                    "source": m["_path"],
                    "tool_name": tool.get("name", "unnamed"),
                    "description": desc,
                })
    for f in context["files"]:
        for m in re.finditer(r"(?:description|prompt|instructions)\s*=\s*(['\"])(.+?)\1",
                              f["content"], re.IGNORECASE | re.DOTALL):
            out.append({
                "source": f["path"],
                "tool_name": "inline",
                "description": m.group(2)[:1000],
            })
    return out
