# Verification trước khi nộp

## Môi trường

- Hệ điều hành: macOS 26.5.2 (build 25F84).
- Python: `3.14.5`.
- Lệnh `gitleaks version`: `8.30.1`.
- Toàn bộ dữ liệu khách hàng, ticket và token dùng trong bài là dữ liệu
  synthetic của lab. Không dùng credential hoặc PII thật.

## Checkpoint 1 — Unsafe baseline

- Kiểm tra: đọc `agent/loop.py`, `agent/tools.py`, `sink/sink.py` và ghi kết quả
  vào `reports/baseline.md`.
- Kết quả: baseline không có identity riêng cho mỗi run, gọi `http_post` không
  qua policy, và sink ghi được request chứa record synthetic của `KH-000999`.
- Bằng chứng: `reports/attack-before.log` có kích thước `298` byte và chứa
  `KH-000999`.

## Checkpoint 2 — Red team

Lệnh:

```bash
python -m agent.check_lure corpus/ticket-90*.md
```

Output cuối:

```text
4/4 lure sẵn sàng.
```

Bốn kỹ thuật và kết quả trước/sau containment được ghi trong
`injection-corpus.md`. Tất cả chỉ gửi tới sink localhost
`127.0.0.1:10024`.

## Checkpoint 3 — Containment, OBO và ledger

Các lệnh kiểm tra:

```bash
python -m pytest tests/test_pii.py -q -s --basetemp=.pytest_tmp/pii
python -m pytest tests/test_policy.py
python -m pytest tests/test_obo.py
python -m pytest tests/test_split.py
python -m pytest tests/test_ledger.py
```

Kết quả PII cuối:

```text
[pii] gold=118 pred=118 tp=118
[pii] precision=1.000 recall=1.000
2 passed in 0.01s
```

Các test policy, OBO, split và ledger đều PASS trong lần chạy toàn bộ suite.
Kết quả chứng minh `support_l1` không đọc hồ sơ restricted, `dpo` vẫn đọc được
hồ sơ hợp lệ, Run B không đọc `KH-000777` chỉ vì ID nằm trong text attacker,
và mọi quyết định ledger đều có `reason`.

## Checkpoint 4 — Supply chain và secret scanning

Các lệnh:

```bash
gitleaks git --config .gitleaks.toml --redact --verbose .
gitleaks dir --config .gitleaks.toml --redact --verbose .
python -m piptools compile --generate-hashes -o requirements.lock requirements.txt
python -m pip install --require-hashes -r requirements.lock
pre-commit install
pre-commit run --all-files
python -m pytest tests/test_supply_chain.py
```

Kết quả:

- Quét lịch sử trả exit code `1` và tìm đúng một token synthetic theo rule
  `lab24-synthetic-token` tại commit `1bdd849`. Đây là kết quả dự kiến.
- Quét thư mục hiện tại trả exit code `0`: `no leaks found`.
- Dependency cài được từ `requirements.lock` với `--require-hashes`.
- Git hook đã được cài tại `.git/hooks/pre-commit`.
- `pre-commit run --all-files`: `Detect hardcoded secrets...Passed`.
- `tests/test_supply_chain.py`: `3 passed`.

## Checkpoint 5 — Chứng minh sau containment

Lệnh kiểm tra cuối:

```bash
python -m pytest tests/ -q --basetemp=.pytest_tmp
python -m agent.check_lure corpus/ticket-90*.md
python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"
pre-commit run --all-files
```

Output:

```text
33 passed in 0.14s
4/4 lure sẵn sàng.
True
Detect hardcoded secrets.................................................Passed
```

Đối chiếu evidence sau lượt replay:

- `reports/attack-before.log`: `298` byte, có request synthetic của
  `KH-000999`.
- `reports/attack-after.log`: `0` byte; không có PII tới sink sau containment.
- `reports/ledger.jsonl`: `verify=True`; tại lần kiểm cuối có `69` entry,
  `0` entry thiếu `reason`, có `3` quyết định `http_post=deny`, và có
  `on_behalf_of=dpo`.
- Ledger không chứa CCCD, số điện thoại, số tài khoản, email hoặc record thô
  của `KH-000999`; đối số tool chỉ được lưu dưới dạng `args_hash`.

## Lỗi đã gặp và cách sửa

1. Sau khi tải Gitleaks trên macOS, cả `gitleaks version` và `gitleaks` từng
   bị kết thúc với thông báo `zsh: killed`. Nguyên nhân là cờ quarantine của
   macOS trên binary đã tải. Đã sửa bằng:

   ```bash
   xattr -d com.apple.quarantine ~/.local/bin/gitleaks
   ```

   Sau đó `gitleaks version` in `8.30.1`.

2. Lần quét lịch sử Gitleaks trả exit code `1`. Không bỏ qua hoặc tắt rule:
   đã kiểm finding là token giả `LAB24-DEMO` được cài sẵn tại commit
   `1bdd849`; vì vậy đây là bằng chứng CP4 mong đợi, không phải credential
   thật hay lỗi còn tồn tại trong HEAD.

3. PII detector ban đầu chưa bao phủ đủ các dạng dữ liệu trong test set.
   Đã bổ sung chuẩn hoá ngữ cảnh tiếng Việt, nhận diện keyword cho CCCD/SĐT/STK
   và xử lý số có dấu cách hoặc dấu gạch. Kết quả cuối đạt precision và recall
   đều bằng `1.000`.

## Giới hạn

Kết quả trên chỉ chứng minh hành vi của `--mock`, principal `--as`, regex PII,
sink localhost và hash-chain ledger trong phạm vi lab. `--as` không phải cơ chế
xác thực production; ledger một file không chống được việc xoá đuôi hoặc viết
lại toàn bộ chuỗi; báo cáo compliance/DPIA-lite không phải chứng nhận tuân thủ
pháp luật cho hệ thống thật.
