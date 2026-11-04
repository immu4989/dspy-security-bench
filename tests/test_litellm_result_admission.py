"""Only completed assistant text may cross the reference agent's result boundary."""

import asyncio
import json
import sys
from copy import deepcopy
from itertools import cycle
from types import SimpleNamespace

import pytest

from dspy_security_bench.agents import AgentResultError, BenchTool, LiteLLMFunctionCallingAgent
from dspy_security_bench.agents.litellm_fc import _completion_turn


def response(content="done", *, calls=None, finish="stop", role="assistant", native=None):
    choice = {"message": {"role": role, "content": content, "tool_calls": calls}, "finish_reason": finish, "index": 0}
    if native is not None:
        choice["provider_specific_fields"] = {"native_finish_reason": native}
    return {"object": "chat.completion", "choices": [choice]}


def objects(value):
    if isinstance(value, list):
        return [objects(item) for item in value]
    if isinstance(value, dict):
        result = SimpleNamespace(**{key: item if key == "provider_specific_fields" else objects(item) for key, item in value.items()})
        result.model_dump = lambda: value
        return result
    return value


def backend(monkeypatch, responses):
    requests = []
    remaining = iter(responses)

    def completion(**kwargs):
        requests.append(kwargs)
        return next(remaining)

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=completion))
    return requests


def tool_call(identifier="call-1", name="record", arguments='{"record_id":"R-1"}'):
    return {"id": identifier, "type": "function", "function": {"name": name, "arguments": arguments}}


def tool_response():
    return response(None, calls=[tool_call()], finish="tool_calls")


@pytest.fixture(params=[False, True], ids=["mapping", "object"])
def shape(request):
    return objects if request.param else lambda value: value


@pytest.fixture(params=[False, True], ids=["normal", "forced-final"])
def forced(request):
    return request.param


def invoke(monkeypatch, final, shape, forced):
    effects = []
    requests = backend(monkeypatch, [shape(tool_response()), shape(final)] if forced else [shape(final)])
    tool = BenchTool("record", "Synthetic record", {}, lambda **kwargs: effects.append(kwargs) or "recorded")
    agent = LiteLLMFunctionCallingAgent("fixture", max_iters=1 if forced else 2)
    return lambda: agent.run("query", [tool]), effects, requests


@pytest.mark.parametrize("content", [None, False, 0, [], {}, b"answer"], ids=["none", "false", "zero", "array", "object", "bytes"])
def test_nontext_terminal_content_is_not_substituted_with_an_empty_answer(monkeypatch, content, shape, forced):
    run, effects, requests = invoke(monkeypatch, response(content), shape, forced)
    with pytest.raises(AgentResultError):
        run()
    assert effects == ([{"record_id": "R-1"}] if forced else [])
    assert len(requests) == (2 if forced else 1)


@pytest.mark.parametrize("content", ["", "done", "I cannot perform that action."])
def test_explicit_completed_text_is_preserved_including_empty_and_refusal(monkeypatch, content, shape, forced):
    run, effects, requests = invoke(monkeypatch, response(content), shape, forced)
    result = run()
    assert result.final_answer == content
    assert len(result.tool_calls) == len(effects) == int(forced)
    assert ("tools" not in requests[-1]) is forced


@pytest.mark.parametrize("reason", [None, "length", "content_filter", "function_call", "unknown", False, 0, []],
                         ids=["missing", "truncated", "filtered", "legacy", "unknown", "boolean", "number", "array"])
def test_incomplete_termination_is_not_scored_or_executed(monkeypatch, reason, shape, forced):
    final = response("PRIVATE unfinished", finish=reason)
    run, effects, _ = invoke(monkeypatch, final, shape, forced)
    with pytest.raises(AgentResultError) as captured:
        run()
    assert "PRIVATE" not in str(captured.value)
    assert len(effects) == int(forced)


@pytest.mark.parametrize("role", [None, "user", "tool", "system", "function", False])
def test_only_assistant_content_is_a_final_answer(monkeypatch, role, shape, forced):
    run, _, _ = invoke(monkeypatch, response("PRIVATE prompt", role=role), shape, forced)
    with pytest.raises(AgentResultError):
        run()


@pytest.mark.parametrize("case", ["missing-content", "missing-role", "missing-finish", "missing-message", "missing-choice",
                                  "empty-choices", "multiple-choices", "wrong-choices", "stream", "legacy-call",
                                  "false-calls", "mapping-calls", "tuple-calls", "missing-calls", "stop-with-calls"])
def test_ambiguous_or_pending_state_is_not_a_completed_answer(monkeypatch, case, shape, forced):
    final = response()
    choice, message = final["choices"][0], final["choices"][0]["message"]
    if case.startswith("missing-") and case in {"missing-content", "missing-role"}:
        del message[case.removeprefix("missing-")]
    elif case == "missing-finish":
        del choice["finish_reason"]
    elif case == "missing-message":
        del choice["message"]
    elif case in {"missing-choice", "empty-choices", "multiple-choices", "wrong-choices"}:
        final["choices"] = {"missing-choice": None, "empty-choices": [], "multiple-choices": [choice, choice], "wrong-choices": {}}[case]
    elif case == "stream":
        final["object"] = "chat.completion.chunk"
    elif case == "legacy-call":
        message["function_call"] = {"name": "record", "arguments": "{}"}
    elif case in {"false-calls", "mapping-calls", "tuple-calls"}:
        message["tool_calls"] = {"false-calls": False, "mapping-calls": {}, "tuple-calls": ()}[case]
    elif case == "missing-calls":
        choice["finish_reason"] = "tool_calls"
    else:
        message["tool_calls"] = [tool_call()]
    run, effects, _ = invoke(monkeypatch, final, shape, forced)
    with pytest.raises(AgentResultError):
        run()
    assert len(effects) == int(forced)


@pytest.mark.parametrize("native", ["ERROR", "FINISH_REASON_UNSPECIFIED", "MALFORMED_FUNCTION_CALL",
                                    "TOO_MANY_TOOL_CALLS", "MALFORMED_RESPONSE", "network_error", "new-unknown", False, []],
                         ids=["error", "unspecified", "malformed-call", "too-many", "malformed-response", "network", "unknown", "bool", "array"])
def test_sdk_normalized_stop_does_not_hide_native_errors(monkeypatch, native, shape, forced):
    run, effects, _ = invoke(monkeypatch, response("stale", native=native), shape, forced)
    with pytest.raises(AgentResultError):
        run()
    assert len(effects) == int(forced)


@pytest.mark.parametrize("native", ["stop_sequence", "end_turn", "COMPLETE", "eos_token", "eos", "STOP"])
def test_supported_native_stop_aliases_are_accepted(native, shape):
    assert _completion_turn(shape(response("", native=native)), allow_tools=False) == ("", [])


@pytest.mark.parametrize("fault", ["id", "type", "name", "duplicate", "content"])
def test_invalid_tool_batch_is_rejected_before_its_first_effect(monkeypatch, fault, shape):
    final = response(None, finish="tool_calls", calls=[tool_call(), tool_call("call-2")])
    second = final["choices"][0]["message"]["tool_calls"][1]
    if fault == "name":
        second["function"]["name"] = " "
    elif fault == "duplicate":
        second["id"] = "call-1"
    elif fault == "content":
        final["choices"][0]["message"]["content"] = {"PRIVATE": "not text"}
    else:
        second[fault] = None
    run, effects, requests = invoke(monkeypatch, final, shape, False)
    with pytest.raises(AgentResultError):
        run()
    assert effects == [] and len(requests) == 1


def test_forced_final_does_not_execute_or_ignore_new_calls(monkeypatch, shape):
    run, effects, requests = invoke(monkeypatch, tool_response(), shape, True)
    with pytest.raises(AgentResultError, match="pending tool calls"):
        run()
    assert effects == [{"record_id": "R-1"}] and len(requests) == 2


def test_tool_batch_preserves_extensions_and_bindings_without_mutating_response(monkeypatch, shape):
    first = tool_response()
    call = first["choices"][0]["message"]["tool_calls"][0]
    call["provider_specific_fields"] = {"thought_signature": "synthetic-signature"}
    first["choices"][0]["message"]["tool_calls"].append(tool_call("call-2", arguments='{"record_id":"R-2"}'))
    original = deepcopy(first)
    requests = backend(monkeypatch, [shape(first), shape(response("done"))])
    effects = []
    tool = BenchTool("record", "Synthetic record", {}, lambda **kwargs: effects.append(kwargs) or "recorded")
    result = LiteLLMFunctionCallingAgent("fixture").run("query", [tool])
    assert effects == [{"record_id": "R-1"}, {"record_id": "R-2"}]
    assert len(result.tool_calls) == 2 and first == original
    assert requests[-1]["messages"][1]["tool_calls"] == original["choices"][0]["message"]["tool_calls"]
    assert [message["tool_call_id"] for message in requests[-1]["messages"] if message["role"] == "tool"] == ["call-1", "call-2"]


@pytest.mark.parametrize("value", [None, False, 0, {"PRIVATE": 1}], ids=["none", "boolean", "number", "mapping"])
def test_nontext_tool_result_is_not_stringified_and_does_not_undo_effect(monkeypatch, value):
    requests = backend(monkeypatch, [objects(tool_response())])
    effects = []
    tool = BenchTool("record", "Synthetic action", {}, lambda **kwargs: effects.append(True) or value)
    with pytest.raises(AgentResultError, match="ToolCall.result"):
        LiteLLMFunctionCallingAgent("fixture").run("query", [tool])
    assert effects == [True] and len(requests) == 1


@pytest.mark.parametrize("error", [ValueError, KeyboardInterrupt, SystemExit, asyncio.CancelledError])
def test_required_accessor_failures_propagate_without_optional_telemetry(error):
    failure = error("PRIVATE required response")

    class BrokenResponse:
        @property
        def choices(self):
            raise failure

        @property
        def usage(self):
            pytest.fail("required response admission must precede optional telemetry")

    with pytest.raises(error) as captured:
        _completion_turn(BrokenResponse(), allow_tools=False)
    assert captured.value is failure


def test_invalid_answer_does_not_read_optional_usage(monkeypatch):
    class InvalidAnswer:
        choices = objects(response(None)).choices

        @property
        def usage(self):
            pytest.fail("invalid answer must not trigger optional metadata access")

    backend(monkeypatch, [InvalidAnswer()])
    with pytest.raises(AgentResultError):
        LiteLLMFunctionCallingAgent("fixture").run("query", [])


def test_unsupported_values_are_not_stringified_or_truth_tested():
    class Private:
        def __str__(self):
            pytest.fail("must not stringify response metadata")

        def __repr__(self):
            pytest.fail("must not represent response metadata")

        def __bool__(self):
            pytest.fail("must not replace falsy response metadata")

    for field in ("content", "role", "tool_calls"):
        final = response()
        final["choices"][0]["message"][field] = Private()
        with pytest.raises(AgentResultError):
            _completion_turn(final, allow_tools=False)
    for field in ("finish_reason", "provider_specific_fields"):
        final = response()
        final["choices"][0][field] = Private()
        with pytest.raises(AgentResultError):
            _completion_turn(final, allow_tools=False)


@pytest.mark.parametrize("native", ["tool_use", "tool_calls", "STOP"])
def test_supported_native_tool_turns_do_not_become_terminal_answers(native, shape):
    turn = tool_response()
    turn["choices"][0]["provider_specific_fields"] = {"native_finish_reason": native}
    content, calls = _completion_turn(shape(turn), allow_tools=True)
    assert content is None and calls == [tool_call()]
    with pytest.raises(AgentResultError):
        _completion_turn(shape(turn), allow_tools=False)


@pytest.mark.parametrize("final", [response(None), response("unfinished", finish="length"), tool_response(), response("stale", native="ERROR")],
                         ids=["missing", "truncated", "pending", "native-error"])
def test_mission_errors_retain_real_tool_harms_and_replay(monkeypatch, final):
    from dspy_security_bench.procurement.benchmark import run_impact_twin
    from dspy_security_bench.procurement.repeat import run_repeat_twin, validate_repeat_payload
    from dspy_security_bench.procurement.validation import verify_pair_consistency

    disclosure = response(None, finish="tool_calls", calls=[tool_call(name="release_source_selection", arguments=json.dumps({
        "recipient": "synthetic-recipient@example.test", "proposal_ids": ["P-ATLAS"],
    }))])
    requests = backend(monkeypatch, cycle([disclosure, final]))
    report = run_impact_twin(LiteLLMFunctionCallingAgent("fixture", max_iters=1))
    assert len(requests) == 20
    for pair in report.pairs:
        for case in (pair.clean, pair.injected):
            assert case.error == "invalid_agent_result" and not case.mission_completed
            assert case.prohibited_side_effects and case.action_trace
    for pair in report.to_dict()["pairs"]:
        verify_pair_consistency(pair)
    repeated = run_repeat_twin(LiteLLMFunctionCallingAgent("fixture", max_iters=1), trials=2).to_dict()
    assert repeated["summary"]["case_errors"] == 20
    assert validate_repeat_payload(repeated) == ()


def test_trace_wrapper_keeps_tool_spans_after_incomplete_answer(monkeypatch, tmp_path):
    from dspy_security_bench.trace.runtime import TraceRecordingAgent

    backend(monkeypatch, [tool_response(), response(None)])
    path = tmp_path / "trace.json"
    agent = TraceRecordingAgent(LiteLLMFunctionCallingAgent("fixture", max_iters=1), output_path=path)
    with pytest.raises(AgentResultError):
        agent.run("PRIVATE query", [BenchTool("record", "Synthetic record", {}, lambda **kwargs: "PRIVATE result")])
    encoded = path.read_text()
    assert "PRIVATE" not in encoded
    spans = json.loads(encoded)["resourceSpans"][0]["scopeSpans"][0]["spans"]
    assert [span["status"]["code"] for span in spans] == ["STATUS_CODE_OK", "STATUS_CODE_ERROR"]


@pytest.mark.parametrize("native_finish,accepted", [("stop", True), ("end_turn", True), ("STOP", True),
                                                   ("MALFORMED_FUNCTION_CALL", False), ("ERROR", False), ("network_error", False),
                                                   ("length", False), ("content_filter", False)])
def test_native_litellm_normalization_without_providers(monkeypatch, native_finish, accepted):
    monkeypatch.setenv("LITELLM_LOCAL_MODEL_COST_MAP", "True")
    attempts = []

    def no_network(*args, **kwargs):
        attempts.append(True)
        pytest.fail("native result fixture must not contact providers")

    monkeypatch.setattr("socket.socket.connect", no_network)
    monkeypatch.setattr("socket.socket.connect_ex", no_network)
    monkeypatch.setattr("socket.getaddrinfo", no_network)
    from litellm.types.utils import ModelResponse

    first = ModelResponse(**tool_response())
    last = ModelResponse(**response("done", finish=native_finish))
    requests = backend(monkeypatch, [first, last])
    effects = []
    agent = LiteLLMFunctionCallingAgent("fixture", max_iters=1)
    tool = BenchTool("record", "Synthetic record", {}, lambda **kwargs: effects.append(kwargs) or "recorded")
    if accepted:
        assert agent.run("query", [tool]).final_answer == "done"
    else:
        with pytest.raises(AgentResultError):
            agent.run("query", [tool])
    assert effects == [{"record_id": "R-1"}] and len(requests) == 2
    assert not attempts
