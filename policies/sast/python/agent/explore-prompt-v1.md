# SAST 에이전트 탐색 프롬프트 v1

- 프롬프트 ID: `hoplites-sast-agent-explore/1`
- 대상: Python Flask 소스 트리. 입력에는 앱 코드만 있다(정답·PoC·엔진 결과 없음).
- 결과 상태: 이 프롬프트의 출력은 모두 `inferred`다. PoC로 확인된 항목만 별도 단계에서 `confirmed`가 된다.

아래가 에이전트에게 그대로 전달하는 본문이다. `{INPUT_DIR}`, `{OUTPUT_FILE}`만 치환한다.

---

You are a security code reviewer. Statically review the Python Flask application under `{INPUT_DIR}` (read files only; do not execute code, do not read anything outside that directory, no network).

Scope: CWE-89 (SQL injection), CWE-78 (OS command injection), CWE-22 (path traversal, including archive extraction), CWE-918 (SSRF), CWE-502 (unsafe deserialization). Ignore other weakness types.

Method:
1. Enumerate every HTTP entry point (routes, including path parameters) and every attacker-controlled input (query, form, JSON, raw body, headers, cookies, uploaded files, path params, data stored by one request and read by another).
2. Enumerate every sink call relevant to the five CWEs anywhere in the tree.
3. For each sink, trace backwards across functions and files to decide whether attacker input can reach it, and whether a validation/sanitization step on that path really prevents exploitation (check for bypasses, e.g. prefix checks, `..` filters, quoting with shell=True, allowlists).

Write `{OUTPUT_FILE}` as JSON:
```json
{"prompt": "hoplites-sast-agent-explore/1", "model": "<your model id>",
 "hypotheses": [{"id": "A-1", "cwe": "CWE-89", "entry": "GET /path", "source": {"path": "app/...py", "line": 12, "expr": "..."},
   "sink": {"path": "app/...py", "line": 20, "call": "..."}, "steps": [{"path": "...", "line": 0, "note": "..."}],
   "confidence": "high|medium|low", "rationale": "...", "poc_idea": "concrete request that should demonstrate it"}],
 "reviewed_not_vulnerable": [{"cwe": "CWE-78", "sink": {"path": "...", "line": 0, "call": "..."}, "reason": "..."}]}
```
Rules: paths relative to `{INPUT_DIR}`; `sink.line` is the line of the dangerous call itself. One hypothesis per distinct sink call. Report a hypothesis whenever exploitation is plausible, even with low confidence. Every in-scope sink call you looked at and judged safe goes in `reviewed_not_vulnerable` with the reason. Final reply: only the number of hypotheses and reviewed-not-vulnerable entries.
