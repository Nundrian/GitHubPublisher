"""Deterministic OpenAI-compatible endpoint that behaves like a tool-calling model.
Used ONLY to drive a real Open WebUI 0.12.5 server in the integration test.
User message 'CALL <function> <json-args>' -> one streamed tool call; after a
tool result arrives it answers with a short text summary."""

import json
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = sys.argv[2] if len(sys.argv) > 2 else None


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path.endswith("/models"):
            return self._json({"object": "list", "data": [{"id": "fake-tool-model", "object": "model",
                                                           "owned_by": "test"}]})
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        msgs = body.get("messages", [])
        if LOG:
            with open(LOG, "a") as f:
                f.write(json.dumps({"tools": [t["function"]["name"] for t in body.get("tools", [])],
                                    "last": msgs[-1] if msgs else None})[:4000] + "\n")
        last = msgs[-1] if msgs else {}
        cid = "chatcmpl-" + uuid.uuid4().hex[:8]
        chunks = []
        content = last.get("content")
        if isinstance(content, list):
            content = " ".join(c.get("text", "") for c in content if isinstance(c, dict))
        if last.get("role") == "user" and str(content).startswith("CALL "):
            _, fn, args = str(content).split(" ", 2)
            chunks.append({"choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": [
                {"index": 0, "id": "call_" + uuid.uuid4().hex[:8], "type": "function",
                 "function": {"name": fn, "arguments": args}}]}, "finish_reason": None}]})
            chunks.append({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})
        else:
            txt = "Tool finished." if last.get("role") == "tool" else "OK."
            chunks.append({"choices": [{"index": 0, "delta": {"role": "assistant", "content": txt},
                                        "finish_reason": None}]})
            chunks.append({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
        if not body.get("stream"):
            msg = {"role": "assistant", "content": None}
            d0 = chunks[0]["choices"][0]["delta"]
            if "tool_calls" in d0:
                msg["tool_calls"] = d0["tool_calls"]
            else:
                msg["content"] = d0.get("content")
            return self._json({"id": cid, "object": "chat.completion", "created": int(time.time()),
                               "model": "fake-tool-model",
                               "choices": [{"index": 0, "message": msg,
                                            "finish_reason": chunks[-1]["choices"][0]["finish_reason"]}]})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for c in chunks:
            c.update({"id": cid, "object": "chat.completion.chunk", "created": int(time.time()),
                      "model": "fake-tool-model"})
            self.wfile.write(f"data: {json.dumps(c)}\n\n".encode())
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
