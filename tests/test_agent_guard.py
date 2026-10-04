import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _agent():
    spec = importlib.util.spec_from_file_location("pw_agent", ROOT / "host-agent" / "agent.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_agent_rejects_bad_token_and_foreign_table(monkeypatch, tmp_path):
    agent = _agent()

    def boom(*_args, **_kwargs):
        raise AssertionError("nft should not be called")

    monkeypatch.setattr(agent, "run_nft", boom)
    token = "t" * 24
    denied = agent.process_request(
        {"op": "apply", "token": "nope", "script": "table inet port_warden {\n}\n"},
        token,
        tmp_path,
        "nft",
    )
    assert denied["ok"] is False
    foreign = agent.process_request(
        {"op": "apply", "token": token, "script": "flush ruleset\n"},
        token,
        tmp_path,
        "nft",
    )
    assert foreign["ok"] is False
    assert "nft should not" not in foreign["error"]
