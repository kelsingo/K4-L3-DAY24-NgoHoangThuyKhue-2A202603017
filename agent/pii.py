"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re
import unicodedata


_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE,
)
_NUMBER_RE = re.compile(r"(?<!\d)\d(?:[ -]?\d){7,15}(?!\d)")


def _plain(text: str) -> str:
    """Normalize Vietnamese context for keyword classification."""
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c)).lower()


def _number_type(text: str, start: int, value: str) -> str | None:
    digits = re.sub(r"\D", "", value)
    context = _plain(text[max(0, start - 60):start])

    # Context wins over length because both CCCD and bank accounts may have
    # exactly 12 digits in the Vietnamese fixtures.
    if re.search(r"(?:stk|so tai khoan)\s*[:#-]?\s*$", context):
        return "VN_BANK_ACCOUNT" if 8 <= len(digits) <= 16 else None
    if re.search(r"cccd(?:\s+cua\s+[^:]{0,40})?\s*[:#-]?\s*$", context):
        return "VN_CCCD" if len(digits) == 12 else None
    if re.search(r"(?:sdt|so dien thoai|dien thoai)(?:\s+[^:]{0,40})?\s*[:#-]?\s*$", context):
        return "VN_PHONE" if digits.startswith("0") and len(digits) in (10, 11) else None

    # Conservative format fallbacks cover standalone values while preserving
    # the contextual distinction above.
    if digits.startswith("0") and len(digits) in (10, 11):
        return "VN_PHONE"
    if len(digits) == 12:
        return "VN_CCCD"
    return None


def detect(text: str) -> list[dict]:
    entities: list[dict] = []

    for match in _EMAIL_RE.finditer(text):
        entities.append({"type": "EMAIL", "start": match.start(), "end": match.end()})

    for match in _NUMBER_RE.finditer(text):
        entity_type = _number_type(text, match.start(), match.group())
        if entity_type:
            entities.append(
                {"type": entity_type, "start": match.start(), "end": match.end()}
            )

    return sorted(entities, key=lambda item: (item["start"], item["end"], item["type"]))


def redact(text: str) -> str:
    redacted = text
    # Work right-to-left so replacements cannot invalidate earlier offsets.
    for entity in sorted(detect(text), key=lambda item: item["start"], reverse=True):
        replacement = f"[REDACTED_{entity['type']}]"
        redacted = redacted[:entity["start"]] + replacement + redacted[entity["end"]:]
    return redacted
