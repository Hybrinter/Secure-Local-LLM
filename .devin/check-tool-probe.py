import json
import sys

raw = sys.stdin.buffer.read(1048577)
if len(raw) > 1048576:
    sys.exit("tool response exceeds the probe limit")
try:
    response = json.loads(raw)
    choices = response["choices"]
    if not isinstance(choices, list) or len(choices) != 1:
        raise ValueError("exactly one choice required")
    choice = choices[0]
    message = choice["message"]
    calls = message["tool_calls"]
    if choice["finish_reason"] != "tool_calls" or message["role"] != "assistant":
        raise ValueError("structured assistant tool response required")
    if not isinstance(calls, list) or len(calls) != 1:
        raise ValueError("exactly one tool call required")
    call = calls[0]
    function = call["function"]
    if call["type"] != "function" or not isinstance(call["id"], str) or not call["id"]:
        raise ValueError("function call identity required")
    if function["name"] != "echo" or not isinstance(function["arguments"], str):
        raise ValueError("echo function with serialized arguments required")
    if json.loads(function["arguments"]) != {"text": "CPU_TOOL_OK"}:
        raise ValueError("unexpected echo arguments")
except (ValueError, TypeError, KeyError, IndexError) as exc:
    sys.exit(f"structured tool probe failed: {exc}")
print("structured tool call verified")
