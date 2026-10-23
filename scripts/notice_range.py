#!/usr/bin/env python3
"""Locate license notice byte ranges inside preserved source files.

A range covers whole lines of a comment block that carries the license
conditions and copyright notice; source code is never part of it. When the
block cannot be located from evidence, the result is unresolved with a reason
instead of a guessed range.
"""

import hashlib
import re

OTP_RULE = "otp-copyright-markers-v1"
REVIEWED_RULE = "reviewed-notice-anchor-v1"
LINE_PREFIXES = (b"%", b"--", b"#", b"//")
BLOCKS = ((b"/*", b"*/"), (b"<!--", b"-->"))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def line_span(raw, first, last):
    """Whole lines from the one containing `first` to the one containing `last`."""
    start = raw.rfind(b"\n", 0, first) + 1
    end = raw.find(b"\n", last)
    return start, len(raw) if end < 0 else end + 1


def comment_style(raw, start, end):
    """Return how [start:end) is a comment, or None if any byte may be code."""
    lines = [x for x in raw[start:end].splitlines() if x.strip()]
    if lines and all(x.lstrip().startswith(LINE_PREFIXES) for x in lines):
        return "line-comment"
    first_end = raw.find(b"\n", start)
    first_end = end if first_end < 0 or first_end > end else first_end
    last_start = raw.rfind(b"\n", start, end - 1) + 1
    for opener, closer in BLOCKS:
        # The range must sit inside one block comment: opened on or before its
        # first line with nothing before the opener, not closed before its last
        # line, and followed by nothing but whitespace if closed inside it.
        o = raw.rfind(opener, 0, first_end)
        if o < 0 or raw[raw.rfind(b"\n", 0, o) + 1 : o].strip():
            continue
        c = raw.find(closer, o + len(opener))
        if c < last_start:
            continue
        if c < end and raw[c + len(closer) : end].strip():
            continue
        return "block-comment"
    return None


def located(path, raw, start, end, rule, style):
    return {
        "notice_path": path,
        "notice_sha256": sha(raw),
        "source_byte_start": start,
        "source_byte_end": end,
        "text_sha256": sha(raw[start:end]),
        "notice_range_status": "located",
        "notice_range_rule": rule,
        "notice_range_style": style,
    }


def unresolved(path, raw, rule, reason, next_action):
    return {
        "notice_path": path,
        "notice_sha256": sha(raw),
        "notice_range_status": "unresolved",
        "notice_range_rule": rule,
        "notice_range_reason": reason,
        "notice_range_next_action": next_action,
    }


def otp_block(path, raw, declared):
    """OTP marks each file notice with %CopyrightBegin% ... %CopyrightEnd%."""
    begin, end_mark = raw.count(b"%CopyrightBegin%"), raw.count(b"%CopyrightEnd%")
    if (begin, end_mark) != (1, 1):
        return unresolved(
            path,
            raw,
            OTP_RULE,
            f"expected one OTP copyright marker pair, found {begin}/{end_mark}",
            "Review the file and add a reviewed notice anchor rule",
        )
    b, e = raw.index(b"%CopyrightBegin%"), raw.index(b"%CopyrightEnd%")
    if b > e:
        return unresolved(
            path, raw, OTP_RULE, "copyright markers out of order", "Review the file notice"
        )
    start, end = line_span(raw, b, e)
    found = sorted(
        set(
            x.decode().strip(" */%#|\t")
            for x in re.findall(rb"SPDX-License-Identifier:\s*(?:\|\s*)?([^\r\n]+)", raw[start:end])
        )
    )
    if found != sorted(declared):
        return unresolved(
            path,
            raw,
            OTP_RULE,
            "marker block declarations differ from the recorded declaration",
            "Review which notice block carries the recorded declaration",
        )
    # A REUSE .license sidecar holds only licensing metadata, never code.
    style = "reuse-sidecar" if path.endswith(".license") else comment_style(raw, start, end)
    if style is None:
        return unresolved(
            path,
            raw,
            OTP_RULE,
            "marker block is not entirely inside a comment",
            "Review the file layout and add a reviewed notice anchor rule",
        )
    return located(path, raw, start, end, OTP_RULE, style)


def reviewed(path, raw, rule):
    """Apply a reviewed anchor rule pinned to the notice file and text hashes."""
    if rule is None:
        return unresolved(
            path,
            raw,
            REVIEWED_RULE,
            "no reviewed notice anchor for this notice file hash",
            "Review the notice file and add a notice_range_rule migration row",
        )
    if sha(raw) != rule["notice_sha256"]:
        return unresolved(
            path,
            raw,
            REVIEWED_RULE,
            "notice file differs from the reviewed file",
            "Review the changed notice file and update the anchor rule",
        )
    if rule["style"] == "license-document":
        start, end = 0, len(raw)
    else:
        first = raw.find(rule["start_marker"].encode())
        last = raw.find(rule["end_marker"].encode(), first) if first >= 0 else -1
        if first < 0 or last < 0:
            return unresolved(
                path,
                raw,
                REVIEWED_RULE,
                "reviewed anchors not found",
                "Review the notice file and update the anchor rule",
            )
        start, end = line_span(raw, first, last)
    # License documents (whole or one section) are not code; source files must
    # pass the comment check.
    style = rule["style"]
    if style == "comment":
        style = comment_style(raw, start, end)
        if style is None:
            return unresolved(
                path,
                raw,
                REVIEWED_RULE,
                "reviewed range is not entirely inside a comment",
                "Review the anchor rule",
            )
    if sha(raw[start:end]) != rule["text_sha256"]:
        return unresolved(
            path,
            raw,
            REVIEWED_RULE,
            "located text differs from the reviewed notice text",
            "Review the anchor rule against the notice file",
        )
    return located(path, raw, start, end, REVIEWED_RULE, style)
