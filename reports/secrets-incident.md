# Secret giả trong lịch sử Git — điền trong checkpoint 4

- **Scanner và phiên bản:** Gitleaks `8.30.1`, chạy với cấu hình
  `.gitleaks.toml` và chế độ `--redact` để không in lại giá trị token.
- **Commit chứa token giả:**
  `1bdd849922156c868a5ee9293d68f5b72e242d2c` (`1bdd849`).
- **File, rule và kết quả quét lịch sử:** Lệnh
  `gitleaks git --config .gitleaks.toml --redact --verbose .` quét 6 commit
  và báo đúng 1 finding trong `lab-fake-secret.txt`, dòng 1, với rule ID
  `lab24-synthetic-token`. Đây là token synthetic vô hiệu được cài sẵn cho
  bài lab, không phải credential thật. Exit code 1 là kết quả dự kiến khi
  scanner tìm thấy finding.
- **Kết quả quét file hiện tại:** Lệnh
  `gitleaks dir --config .gitleaks.toml --redact --verbose .` báo
  `no leaks found`; file chứa token giả đã không còn trong HEAD.
- **Nếu đây là credential thật, cần xử lý thế nào:** Thu hồi hoặc rotate
  credential ngay tại hệ thống phát hành, điều tra log để xác định phạm vi
  sử dụng trái phép, cập nhật nơi tiêu thụ credential mới, rồi làm sạch lịch
  sử Git khi quy trình ứng phó sự cố yêu cầu. Không đưa giá trị thật vào báo
  cáo hoặc commit khác.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:** Xoá file
  chỉ loại nó khỏi phiên bản hiện tại; giá trị vẫn có trong lịch sử Git và
  các clone/fork/cache. Pin dependency và hook giúp tái lập build và ngăn
  commit mới, nhưng không làm credential đã lộ mất hiệu lực. Chỉ thao tác
  revoke/rotate tại bên phát hành mới vô hiệu hoá credential đó.
