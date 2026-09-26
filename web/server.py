"""VinBank Guard Lab — local console.

Chạy từ gốc repo:

    .venv\\Scripts\\python.exe web/server.py

Mở http://127.0.0.1:8765
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from google.genai import types
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from assignment.pipeline import is_egress_allowed  # noqa: E402
from assignment.rate_limiter import RateLimitPlugin  # noqa: E402
from attacks.attacks import adversarial_prompts, run_attacks  # noqa: E402
from guardrails.input_guardrails import (  # noqa: E402
    InputGuardrailPlugin,
    detect_injection,
    topic_filter,
)
from guardrails.output_guardrails import content_filter  # noqa: E402

OUT = ROOT / "outputs"
STATIC = Path(__file__).resolve().parent / "static"

app = FastAPI(title="VinBank Guard Lab")
app.mount("/static", StaticFiles(directory=STATIC), name="static")

_rate = RateLimitPlugin(max_requests=10, window_seconds=60)
_rate_stats = {"sent": 0, "passed": 0, "blocked": 0}
_agents: dict[str, tuple] = {}


class TextIn(BaseModel):
    text: str = ""


class EgressIn(BaseModel):
    destination: str = ""
    payload: str = ""


class RateIn(BaseModel):
    user_id: str = "student"
    text: str = "What is my account balance?"


class AttackIn(BaseModel):
    target: str = Field(pattern="^(red_default|red_advance)$")
    prompt: str
    category: str = "Custom"


def _read_json(path: Path):
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _content(text: str) -> types.Content:
    return types.Content(role="user", parts=[types.Part.from_text(text=text)])


class _Ctx:
    def __init__(self, user_id: str):
        self.user_id = user_id


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/overview")
def overview():
    results = _read_json(OUT / "results.json") or {}
    attacks = _read_json(OUT / "attack_results.json") or {}
    metrics = _read_json(OUT / "metrics.json")
    safe = results.get("safe_queries") or []
    attack_q = results.get("attack_queries") or []
    edges = results.get("edge_cases") or []
    summary = attacks.get("summary") or {}
    unsafe = attacks.get("unsafe_attacks") or []
    guards = attacks.get("guards_attacks") or []
    return {
        "framework": results.get("framework"),
        "defense": {
            "safe_total": len(safe),
            "safe_blocked": sum(1 for q in safe if q.get("blocked")),
            "attack_total": len(attack_q),
            "attack_blocked": sum(1 for q in attack_q if q.get("blocked")),
            "edge_total": len(edges),
            "edge_blocked": sum(1 for q in edges if q.get("blocked")),
            "rate_limit": results.get("rate_limit"),
        },
        "red_team": {
            "llm_provider": attacks.get("llm_provider"),
            "llm_model": attacks.get("llm_model"),
            "unsafe_leaked": summary.get("unsafe_leaked", sum(1 for r in unsafe if r.get("leaked"))),
            "unsafe_total": len(unsafe),
            "guards_leaked": summary.get("guards_leaked", sum(1 for r in guards if r.get("leaked"))),
            "guards_total": len(guards),
        },
        "metrics": metrics,
        "files": {
            "results": (OUT / "results.json").is_file(),
            "audit": (OUT / "audit_log.json").is_file(),
            "metrics": (OUT / "metrics.json").is_file(),
            "attacks": (OUT / "attack_results.json").is_file(),
        },
    }


@app.get("/api/prompts")
def prompts():
    return [
        {"id": item["id"], "category": item["category"], "input": item["input"]}
        for item in adversarial_prompts
    ]


@app.post("/api/check-input")
async def check_input(body: TextIn):
    injection = detect_injection(body.text)
    topic = topic_filter(body.text)
    plugin = InputGuardrailPlugin()
    blocked = await plugin.on_user_message_callback(
        invocation_context=None,
        user_message=_content(body.text),
    )
    message = ""
    if blocked and blocked.parts:
        message = blocked.parts[0].text or ""
    layer = None
    if injection == "BLOCK":
        layer = "injection"
    elif topic == "BLOCK":
        layer = "topic"
    return {
        "injection": injection,
        "topic": topic,
        "decision": "BLOCK" if blocked else "ALLOW",
        "layer": layer,
        "message": message,
    }


@app.post("/api/check-output")
def check_output(body: TextIn):
    return content_filter(body.text)


@app.post("/api/egress")
def egress(body: EgressIn):
    allowed = is_egress_allowed(body.destination, body.payload)
    return {"allowed": allowed}


@app.post("/api/rate-limit")
async def rate_limit(body: RateIn):
    user_id = (body.user_id or "student").strip() or "student"
    _rate_stats["sent"] += 1
    result = await _rate.on_user_message_callback(
        invocation_context=_Ctx(user_id),
        user_message=_content(body.text or "What is my account balance?"),
    )
    blocked = result is not None
    message = ""
    if blocked and result.parts:
        message = result.parts[0].text or ""
        _rate_stats["blocked"] += 1
    else:
        _rate_stats["passed"] += 1
    used = len(_rate.user_windows.get(user_id, []))
    return {
        "blocked": blocked,
        "message": message,
        "user_id": user_id,
        "used": used,
        "max_requests": _rate.max_requests,
        "window_seconds": _rate.window_seconds,
        **_rate_stats,
    }


@app.post("/api/rate-limit/reset")
def rate_reset():
    _rate.user_windows.clear()
    _rate.blocked_count = 0
    _rate.total_count = 0
    _rate_stats.update(sent=0, passed=0, blocked=0)
    return {"ok": True, **_rate_stats, "max_requests": _rate.max_requests}


@app.get("/api/audit")
def audit(limit: int = 8):
    rows = _read_json(OUT / "audit_log.json") or []
    trimmed = []
    for row in rows[-max(1, min(limit, 30)):]:
        trimmed.append({
            "user_id": row.get("user_id"),
            "input": (row.get("input") or "")[:140],
            "output": (row.get("output") or "")[:180],
            "blocked": bool(row.get("blocked")),
            "layer": row.get("layer"),
            "latency_ms": row.get("latency_ms"),
            "started_at": row.get("started_at"),
        })
    return {"total": len(rows), "rows": list(reversed(trimmed))}


class ChatIn(BaseModel):
    agent: str = Field(pattern="^(blue|red_default|red_advance)$")
    text: str


def _agent_pair(key: str):
    if key not in _agents:
        if key == "blue":
            from agents.agent import create_blue_agent
            from assignment.pipeline import build_production_plugins
            plugins = [
                plugin for plugin in build_production_plugins(use_llm_judge=False)
                if getattr(plugin, "name", "") != "rate_limiter"
            ]
            _agents[key] = create_blue_agent(plugins)
        elif key == "red_default":
            from agents.agent import create_red_agent_default
            _agents[key] = create_red_agent_default()
        else:
            from agents.guards_agent import create_red_agent_advance
            _agents[key] = create_red_agent_advance()
    return _agents[key]


async def _complete(agent, runner, text: str) -> str:
    from core.utils import chat_with_agent

    try:
        reply, _session = await chat_with_agent(agent, runner, text)
        return reply or ""
    except Exception as exc:
        if "No endpoints found" in str(exc) and getattr(runner, "model", "") == "liquid/lfm-2.5-2.6b":
            runner.model = "liquid/lfm-2.5-2.6b:free"
            reply, _session = await chat_with_agent(agent, runner, text)
            return reply or ""
        raise


@app.post("/api/chat")
async def chat(body: ChatIn):
    text = body.text.strip()
    if not text:
        return {"status": "error", "label": "Lỗi", "reply": "Nhập một câu trước khi gửi.", "detail": ""}

    if body.agent == "blue":
        injection = detect_injection(text)
        topic = topic_filter(text)
        detail = f"Injection {injection} · Topic {topic}"
        if injection == "BLOCK" or topic == "BLOCK":
            plugin = InputGuardrailPlugin()
            blocked = await plugin.on_user_message_callback(
                invocation_context=None,
                user_message=_content(text),
            )
            message = ""
            if blocked and blocked.parts:
                message = blocked.parts[0].text or ""
            return {
                "status": "block",
                "label": "Chặn trước LLM",
                "reply": message,
                "detail": detail,
            }
        try:
            agent, runner = _agent_pair("blue")
            reply = await _complete(agent, runner, text)
        except Exception:
            return {
                "status": "error",
                "label": "Lỗi",
                "reply": "Không gọi được model Blue. Kiểm tra OPENROUTER_API_KEY trong .env.",
                "detail": detail,
            }
        filtered = content_filter(reply)
        redacted = "[REDACTED]" in (filtered.get("redacted") or "") or "[REDACTED]" in reply
        shown = filtered.get("redacted") or reply
        if redacted:
            return {"status": "redact", "label": "Đã che secret", "reply": shown, "detail": detail}
        return {"status": "allow", "label": "Cho qua", "reply": shown, "detail": detail}

    try:
        agent, runner = _agent_pair(body.agent)
        results = await run_attacks(
            agent,
            runner,
            prompts=[{"id": 1, "category": "Chat", "input": text}],
            target_name=body.agent,
            save_json=False,
        )
    except Exception:
        return {
            "status": "error",
            "label": "Lỗi",
            "reply": "Không gọi được model Red. Kiểm tra OPENAI_API_KEY trong .env.",
            "detail": "",
        }
    row = results[0]
    reply = row.get("response") or row.get("response_preview") or ""
    if row.get("error"):
        return {"status": "error", "label": "Lỗi", "reply": reply, "detail": row.get("blocked_at") or ""}
    if row.get("leaked"):
        return {"status": "leak", "label": "Lộ secret demo", "reply": reply, "detail": row.get("blocked_at") or ""}
    if row.get("blocked") or row.get("blocked_input"):
        return {"status": "block", "label": "Guardrail chặn", "reply": reply, "detail": row.get("blocked_at") or ""}
    lowered = reply.lower()
    if "can't assist" in lowered or "cannot" in lowered or "can't help" in lowered:
        return {"status": "refuse", "label": "Model từ chối", "reply": reply, "detail": "Không lộ secret."}
    return {"status": "allow", "label": "Không lộ secret", "reply": reply, "detail": row.get("blocked_at") or ""}


@app.post("/api/attack")
async def attack(body: AttackIn):
    prompt = body.prompt.strip()
    if not prompt:
        return {"error": "Nhập prompt trước khi chạy."}
    if body.target not in _agents:
        if body.target == "red_default":
            from agents.agent import create_red_agent_default
            _agents[body.target] = create_red_agent_default()
        else:
            from agents.guards_agent import create_red_agent_advance
            _agents[body.target] = create_red_agent_advance()
    agent, runner = _agents[body.target]
    results = await run_attacks(
        agent,
        runner,
        prompts=[{
            "id": 1,
            "category": body.category or "Custom",
            "input": prompt,
        }],
        target_name=body.target,
        save_json=False,
    )
    row = results[0]
    return {
        "target": body.target,
        "category": row.get("category"),
        "leaked": bool(row.get("leaked")),
        "blocked": bool(row.get("blocked")),
        "blocked_input": bool(row.get("blocked_input")),
        "layer": row.get("layer"),
        "blocked_at": row.get("blocked_at"),
        "response_preview": (row.get("response") or row.get("response_preview") or "")[:900],
        "error": row.get("error"),
    }


if __name__ == "__main__":
    import uvicorn

    print("VinBank Guard Lab → http://127.0.0.1:8765")
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")
