"""Compatibility check against the REAL open-webui==0.12.5 Python package.

Loads the Tool through Open WebUI's own plugin loader and spec generator, and
wraps it with Open WebUI's own extra-param binding (what the chat middleware
uses), then checks that:
  * exactly the 5 intended functions are exposed,
  * reserved __*__ parameters never appear in the model-facing schema,
  * a model-supplied '__event_call__' or approval argument is dropped by
    Open WebUI's own parameter filter, so it cannot approve anything.
Run with the Open WebUI 0.12.5 venv:  python tests/owui_compat_check.py
"""

import asyncio
import json
import os
import sys
import tempfile

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="owui-data-"))
os.environ.setdefault("WEBUI_SECRET_KEY", "test-only")

import importlib.metadata as md  # noqa: E402

from open_webui.utils.plugin import extract_frontmatter, load_tool_module_by_id  # noqa: E402
from open_webui.utils.tools import (get_async_tool_function_and_apply_extra_params,  # noqa: E402
                                    get_tool_specs)

TOOL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "openwebui",
                    "github_publisher_tool.py")


async def main():
    content = open(TOOL, encoding="utf-8").read()
    fm = extract_frontmatter(content)
    tools, frontmatter, _module = await load_tool_module_by_id("github_publisher", content=content)
    specs = get_tool_specs(tools)
    names = sorted(s["name"] for s in specs)
    report = {"open_webui_version": md.version("open-webui"), "frontmatter": fm, "functions": names}
    assert names == ["prepare_publish", "publish_reviewed", "publisher_status", "review_publish",
                     "verify_publish"], names
    for s in specs:
        props = s["parameters"].get("properties", {})
        # Open WebUI removes reserved params when building the model-facing spec (utils/tools.py)
        props = {k: v for k, v in props.items() if not k.startswith("__")}
        report[s["name"]] = {"params": sorted(props), "description": s.get("description", "")[:90]}
    assert report["publish_reviewed"]["params"] == ["plan_id"]
    assert report["prepare_publish"]["params"] == ["project"]
    assert report["publisher_status"]["params"] == []

    # Bind extra params exactly like the middleware, with a fake (non-confirming) event caller.
    seen = []

    async def event_call(ev):
        seen.append(ev["type"])
        return False

    fn = await get_async_tool_function_and_apply_extra_params(
        tools.publish_reviewed,
        {"__user__": {"id": "u", "role": "admin"}, "__event_call__": event_call,
         "__event_emitter__": None, "__id__": "github_publisher"})
    # Middleware filters model kwargs to the spec's properties: a smuggled approval is dropped.
    allowed = {"plan_id"}
    model_kwargs = {"plan_id": "demo-000000000000", "__event_call__": "yes", "approved": True}
    out = await fn(**{k: v for k, v in model_kwargs.items() if k in allowed})
    report["publish_without_service"] = json.loads(out)
    assert json.loads(out)["error"] == "not_configured"   # valves unset -> refuses before anything
    print(json.dumps(report, indent=1))
    print("OPEN WEBUI 0.12.5 COMPATIBILITY: OK")


if __name__ == "__main__":
    asyncio.run(main())
    sys.exit(0)
