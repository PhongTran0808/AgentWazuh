# RÀNG BUỘC AN TOÀN HUMAN-IN-THE-LOOP (HITL SAFETY)

1. **NO DIRECT PRODUCTION WRITE**: Không bao giờ tự ý ghi hoặc áp dụng trực tiếp file XML rule lên hệ thống production Wazuh Manager mà chưa có nút nhấn xác nhận từ người dùng.
2. **STAGING PENDING AREA**: Mọi cấu hình XML mới phải được lưu tạm tại khu vực đệm `./config/pending_rules/`.
3. **DRY-RUN MANDATORY**: Mọi rule nháp phải chạy qua bước Sandbox Dry-Run với dữ liệu log lịch sử để tính toán tỷ lệ khớp trước khi hiển thị cho người dùng duyệt.
4. **SESSION STATE RETENTION**: Khi đang mở Form Cấu Hình, nếu người dùng đặt câu hỏi chen ngang, hệ thống phải giữ nguyên trạng thái nháp (`active_form_session`) để tiếp tục sau khi giải đáp xong.
