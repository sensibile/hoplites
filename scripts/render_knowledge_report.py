#!/usr/bin/env python3
"""Render local knowledge review or pinned report JSON as a self-contained HTML file."""

import argparse
import html
import json
from pathlib import Path
from hoplites_knowledge import RULE, TENANT, read_json, sha, encode

LABELS = {
    "confirmed": "확인됨",
    "inferred": "추정됨",
    "unknown": "미확인",
    "unresolved": "미해결",
    "not-verified": "미검증",
    "not-assessed": "미평가",
}
ACTIONS = {
    "Verify whether the delivered artifact includes this code or only uses it during production.": "배포물에 포함된 코드인지, 제작 과정에서만 사용한 것인지 확인",
    "Determine applicable terms for this target from the preserved source and build evidence.": "보존된 원문·빌드 근거로 이 대상에 적용되는 조건 확인",
    "Record the selected license branch for this target; preserve alternatives.": "선택한 라이선스 분기와 선택 근거 기록",
    "Check the exception and its conditions for this target.": "이 대상에 적용되는 예외와 조건 확인",
    "Review notice, attribution, source provision and modification requirements separately for this target and distribution mode.": "이 대상과 배포 방식에 맞춰 고지·저작자 표시·소스 제공·수정 관련 요구를 각각 검토",
}


def esc(value):
    return html.escape(str(value), quote=True)


def label(value):
    return LABELS.get(value, str(value))


def draft(bundle):
    if bundle.get("schema") != RULE or bundle.get("tenant") != TENANT:
        raise ValueError("invalid knowledge bundle")
    return {
        "schema": RULE,
        "tenant": TENANT,
        "status": "offline-draft",
        "authentication": "not-connected",
        "artifact": bundle["artifact"],
        "subject": bundle["subject"],
        "knowledge_version": None,
        "snapshot_sha256": None,
        "bundle_sha256": sha(encode(bundle)),
        "input_sha256": bundle["input_sha256"],
        "rule_version": RULE,
        "records": {
            op["record"]["id"]: op["record"]
            for op in bundle["write_template"]["request"]["operations"]
            if op["op"] == "put"
        },
        "links": [
            op["link"]
            for op in bundle["write_template"]["request"]["operations"]
            if op["op"] == "link"
        ],
    }


def render(value):
    if (
        value.get("schema") != RULE
        or value.get("tenant") != TENANT
        or value.get("status") not in {"offline-draft", "local-authenticated"}
    ):
        raise ValueError("unsupported report identity or assurance state")
    records = value["records"]
    evidence = []
    for r in records.values():
        if r["kind"] != "evidence":
            continue
        try:
            item = json.loads(r["content"])
        except ValueError:
            item = {}
        if isinstance(item, dict) and r.get("subject") == value["subject"]:
            evidence.append(item)
    targeted = [
        e
        for e in evidence
        if isinstance(e.get("component"), dict) and e["component"].get("purl") == value["subject"]
    ]
    if len(targeted) != 1:
        raise ValueError("target component evidence must resolve uniquely")
    component = targeted[0]["component"]
    installation = targeted[0].get("installation")
    title = component.get("name", "구성요소") + " 조사 보고서"
    parts = [
        f"""<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title>
<style>body{{font:16px/1.65 system-ui,sans-serif;background:#f5f6f8;color:#202632;margin:0}}main{{max-width:1080px;margin:auto;padding:32px 24px}}h1{{font-size:30px}}h2{{font-size:22px;margin-top:32px}}section,.notice{{background:white;border:1px solid #d8dee7;border-radius:10px;padding:20px;margin:16px 0}}.notice{{background:#fff5dc}}table{{width:100%;border-collapse:collapse}}td,th{{padding:10px;text-align:left;border-bottom:1px solid #d8dee7;vertical-align:top}}code,pre{{font:13px/1.55 ui-monospace,monospace;overflow-wrap:anywhere}}pre{{white-space:pre-wrap}}.muted{{color:#566174}}.badge{{display:inline-block;background:#e8edf4;padding:2px 8px;border-radius:4px}}@media(max-width:700px){{main{{padding:16px}}table{{display:block;overflow:auto}}}}</style><main><h1>{esc(title)}</h1>"""
    ]
    version = value.get("knowledge_version")
    authenticated = value["status"] == "local-authenticated"
    if authenticated and value.get("authentication") != "local-service-bearer":
        raise ValueError("report authentication state differs")
    notice = "로컬 인증 서비스 조회본" if authenticated else "운영 연결 전 검토본"
    description = (
        "호플리테스 테넌트의 인증된 로컬 서비스 응답을 조회했습니다. 라이선스 의무 이행과 배포 승인은 별도로 확인해야 합니다. "
        if authenticated
        else "인증된 테넌트 조회·라이선스 의무 이행·배포 승인을 검증한 보고서가 아닙니다. "
    )
    parts.append(
        '<div class="notice"><strong>'
        + notice
        + "</strong><br>"
        + description
        + (
            "지식 저장 전 적재 검토 묶음입니다."
            if version is None
            else f"지식 버전 {esc(version)}의 결과를 고정했습니다."
        )
        + "</div>"
    )
    parts.append(
        f"<section><strong>{esc(component.get('name', ''))} {esc(component.get('version', ''))}</strong><br><code>{esc(value['subject'])}</code><p>플랫폼: {esc(value['artifact']['platform'])}<br>이미지: <code>{esc(value['artifact']['image_manifest'])}</code></p></section>"
    )
    parts.append("<h2>이 항목은 무엇인가</h2><section>")
    if installation:
        if installation["documentation_paths_only"]:
            parts.append(
                "설치 목록은 패키지의 공통 문서 경로와 상위 디렉터리로 구성됩니다. 컴파일러 실행 파일은 이 목록에 없습니다."
            )
        else:
            parts.append(
                "설치 목록에 문서 이외 경로가 있습니다. 파일 역할을 아래 근거로 확인해야 합니다."
            )
        deps = installation["reverse_dependency_declarations"]
        parts.append(
            "<p>설치된 패키지 DB에서 이 패키지를 요구하는 항목: "
            + (
                ", ".join(esc(d["package"] + " " + d["version"]) for d in deps)
                if deps
                else "해당 선언 없음"
            )
            + "</p>"
        )
        parts.append(
            '<p class="muted">패키지 이름만으로 삭제 여부를 결정할 수 없습니다. 삭제를 검토한다면 의존 패키지와 실행 영향을 확인해야 합니다. 이 목록은 의존성 해결기 결과가 아닙니다.</p><details><summary>설치 파일·의존 선언·근거 해시</summary><pre>'
            + esc(json.dumps(installation, ensure_ascii=False, indent=2))
            + "</pre></details>"
        )
    else:
        parts.append("설치 파일·의존 선언 근거가 이 묶음에 없습니다. 역할 조사가 남아 있습니다.")
    parts.append("</section><h2>대상별 조건과 남은 작업</h2>")
    questions = [r for r in records.values() if r["kind"] == "question"]
    for r in questions:
        try:
            q = json.loads(r["content"])
            if not isinstance(q, dict):
                raise ValueError("question payload is not an object")
        except (ValueError, TypeError):
            q = {"subject": r["subject"], "next_actions": [r["content"]]}
        if "scope_id" not in q:
            prompt = r["content"]
            if prompt == "Which conditions apply to the exact documents shipped in this image?":
                prompt = "이 이미지에 실제 배포된 문서에는 어떤 조건이 적용되는가?"
            parts.append(
                "<section><strong>남은 조사 질문</strong><p>"
                + esc(prompt)
                + "</p><p>담당자 미지정</p><details><summary>원문 질문과 근거</summary><pre>"
                + esc(json.dumps(r, ensure_ascii=False, indent=2))
                + "</pre></details></section>"
            )
            continue
        parts.append(
            "<section><strong>"
            + esc(q.get("subject", r["subject"]))
            + "</strong><table><tr><th>선언된 조건</th><td><code>"
            + esc(q.get("declared_expression") or "미확인")
            + "</code></td></tr>"
        )
        for field, name in [
            ("inclusion", "실제 포함"),
            ("applicability", "적용 판단"),
            ("fulfillment", "이행 확인"),
        ]:
            parts.append(
                "<tr><th>" + name + "</th><td>" + esc(label(q.get(field, "unknown"))) + "</td></tr>"
            )
        parts.append(
            '</table><p><span class="badge">'
            + esc(label(r["assessment"]))
            + "</span> · 담당자 미지정</p><ol>"
        )
        for action in q.get("next_actions", []):
            parts.append("<li>" + esc(ACTIONS.get(action, action)) + "</li>")
        parts.append(
            "</ol><details><summary>원문 작업 기록</summary><pre>"
            + esc(r["content"])
            + "</pre></details></section>"
        )
    parts.append("<h2>판단·근거·관계</h2><section>")
    for identifier, r in sorted(records.items()):
        author = r["author"]
        parts.append(
            "<details><summary>"
            + esc(identifier + " · " + r["kind"] + " · " + label(r["assessment"]))
            + "</summary><p>작성: "
            + esc(author["name"])
            + " / "
            + esc(author.get("version"))
            + "</p><pre>"
            + esc(json.dumps(r, ensure_ascii=False, indent=2))
            + "</pre></details>"
        )
    parts.append(
        "<pre>"
        + esc(json.dumps(value["links"], ensure_ascii=False, indent=2))
        + "</pre></section><h2>재현 기준</h2><section><pre>"
        + esc(
            json.dumps(
                {
                    k: value.get(k)
                    for k in [
                        "tenant",
                        "authentication",
                        "knowledge_version",
                        "snapshot_sha256",
                        "bundle_sha256",
                        "rule_version",
                        "input_sha256",
                    ]
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        + "</pre></section></main></html>\n"
    )
    return "".join(parts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--bundle", type=Path)
    group.add_argument("--report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value, _ = read_json(args.bundle or args.report)
        content = render(draft(value) if args.bundle else value)
        with args.output.open("x", encoding="utf-8") as output:
            output.write(content)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
