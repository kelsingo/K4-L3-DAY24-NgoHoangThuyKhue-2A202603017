"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_PATH = Path(__file__).resolve().parent.parent / "data" / "customers.json"
_TICKET_FILE_RE = re.compile(r"^ticket-(\d+)(?:[a-z])?\.md$", re.IGNORECASE)


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _args_hash(arguments: object) -> str:
    encoded = json.dumps(arguments, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _record_decision(
    *, ledger_path: Path, agent_id: str, run_id: str, tool: str,
    arguments: object, classification: str, allowed: bool, reason: str,
    principal_id: str, expires_at: str,
) -> None:
    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id,
            "tool": tool,
            "args_hash": _args_hash(arguments),
            "classification": classification,
            "decision": "allow" if allowed else "deny",
            "reason": reason,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        },
        ledger_path,
    )


def _decide_and_record(
    *, context: policy.PolicyContext, ledger_path: Path, run_id: str,
    tool: str, arguments: object, classification: str, expires_at: str,
) -> bool:
    allowed, reason = policy.check(context)
    _record_decision(
        ledger_path=ledger_path,
        agent_id=context.agent_owner,
        run_id=run_id,
        tool=tool,
        arguments=arguments,
        classification=classification,
        allowed=allowed,
        reason=reason,
        principal_id=context.principal_id,
        expires_at=expires_at,
    )
    return allowed


def _ticket_ids_from_filenames(docs: list[dict]) -> list[int]:
    ticket_ids = set()
    for doc in docs:
        match = _TICKET_FILE_RE.fullmatch(str(doc.get("id", "")))
        if match:
            ticket_ids.add(int(match.group(1)))
    return sorted(ticket_ids)


def _customers_for_tickets(ticket_ids: list[int]) -> list[str]:
    customers = json.loads(CUSTOMERS_PATH.read_text(encoding="utf-8"))
    wanted = set(ticket_ids)
    return [
        str(customer["customer_id"])
        for customer in customers
        if wanted.intersection(customer.get("related_tickets", []))
    ]


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    invocation_id = uuid.uuid4().hex
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    # Run A owns untrusted document access only.
    run_a_id = f"run-a-{invocation_id}"
    run_a_agent = "lab24-agent/run-a"
    search_context = policy.PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner=run_a_agent,
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=("search_docs",),
        parent_scopes=(),
        expires_at=expires_at,
    )
    if _decide_and_record(
        context=search_context,
        ledger_path=ledger_path,
        run_id=run_a_id,
        tool="search_docs",
        arguments={"query": message},
        classification="internal",
        expires_at=expires_at,
    ):
        docs = tools.search_docs(message)
    else:
        docs = []

    combined_untrusted_text = "\n\n".join(str(doc.get("text", "")) for doc in docs)
    injected = llm.find_injection(combined_untrusted_text)

    # Only IDs parsed from trusted filename structure cross into Run B. Neither
    # document prose nor customer IDs extracted by the model cross this boundary.
    ticket_ids = _ticket_ids_from_filenames(docs)
    customer_ids = _customers_for_tickets(ticket_ids)
    safe_docs = [
        {**doc, "text": pii.redact(str(doc.get("text", "")))}
        for doc in docs
    ]

    # Run B owns private-store access but has no egress capability.
    run_b_id = f"run-b-{invocation_id}"
    run_b_agent = "lab24-agent/run-b"
    records = []
    for customer_id in customer_ids:
        read_context = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=run_b_agent,
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=("read_customer",),
            parent_scopes=(),
            expires_at=expires_at,
        )
        if _decide_and_record(
            context=read_context,
            ledger_path=ledger_path,
            run_id=run_b_id,
            tool="read_customer",
            arguments={"customer_id": customer_id},
            classification="restricted",
            expires_at=expires_at,
        ):
            records.append(tools.read_customer(customer_id))

    # Preserve the observable attack attempt so the PEP produces explicit deny
    # evidence, but never execute the network tool when restricted data is held.
    if injected is not None and records:
        egress_run_id = f"run-egress-{invocation_id}"
        egress_agent = "lab24-agent/egress"
        post_context = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=egress_agent,
            delegation_depth=0,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=("http_post",),
            parent_scopes=(),
            expires_at=expires_at,
        )
        if _decide_and_record(
            context=post_context,
            ledger_path=ledger_path,
            run_id=egress_run_id,
            tool="http_post",
            arguments={"url": injected.target_url, "record_count": len(records)},
            classification="restricted",
            expires_at=expires_at,
        ):
            tools.http_post(injected.target_url, {"records": records})

    return llm.summarize(safe_docs)
