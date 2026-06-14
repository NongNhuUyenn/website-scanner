# Công cụ Quét Bảo Mật Ứng Dụng Web

Đây là công cụ kiểm thử bảo mật ứng dụng web tự động được xây dựng trong khuôn khổ môn học. Người dùng chỉ cần nhập địa chỉ website vào giao diện, công cụ sẽ tự động thực hiện toàn bộ quy trình quét và trả về danh sách lỗ hổng bảo mật được phân loại theo tiêu chuẩn quốc tế.

## Giải quyết vấn đề

Công cụ này tự động hóa quá trình quét và trình bày kết quả theo hai tầng phục vụ hai nhóm người dùng khác nhau.

## Cách hoạt động

Khi người dùng nhập URL và bấm quét, hệ thống thực hiện tuần tự ba bước. Đầu tiên, công cụ tự động đăng nhập vào ứng dụng mục tiêu để lấy phiên làm việc hợp lệ, cho phép quét được cả những trang yêu cầu đăng nhập thay vì chỉ quét phần công khai bên ngoài. Tiếp theo, OWASP ZAP duyệt toàn bộ cấu trúc ứng dụng để lập bản đồ các trang, form và tham số. Cuối cùng, ZAP gửi hàng nghìn payload kiểm thử vào từng tham số để phát hiện lỗ hổng. Kết quả được xử lý, phân loại và hiển thị trên giao diện web.

## Công nghệ sử dụng

OWASP ZAP phiên bản 2.17.0 đóng vai trò engine quét, thực hiện toàn bộ công việc phát hiện lỗ hổng thông qua kỹ thuật DAST (tấn công thử nghiệm từ bên ngoài mà không cần truy cập mã nguồn). Python và Flask xử lý phần backend, nhận yêu cầu từ giao diện, điều phối ZAP qua REST API và xử lý kết quả trả về. Docker dùng để chạy ZAP trong môi trường container độc lập. Kết quả được phân loại theo OWASP Top 10 2025, bộ tiêu chuẩn quốc tế liệt kê 10 nhóm rủi ro bảo mật phổ biến nhất đối với ứng dụng web, được cập nhật định kỳ bởi tổ chức OWASP và được công nhận rộng rãi trong ngành.

## Kết quả hiển thị

Kết quả được trình bày qua hai tầng. Tầng tổng quan hiển thị số lượng lỗ hổng theo mức độ nguy hiểm, mức rủi ro chung của toàn bộ ứng dụng và danh sách các phát hiện sắp xếp từ nghiêm trọng đến ít nghiêm trọng, phù hợp cho người muốn nắm bức tranh tổng thể. Tầng chi tiết kỹ thuật cho phép mở rộng từng lỗ hổng để xem địa chỉ URL bị ảnh hưởng, mã định danh lỗ hổng theo chuẩn CWE của MITRE, nhãn phân loại OWASP Top 10 2025, quy trình kiểm tra thủ công theo OWASP WSTG, độ tin cậy của cảnh báo, giải pháp kỹ thuật và liên kết tra cứu đến NVD NIST và MITRE CWE, phục vụ người cần thông tin đầy đủ để xử lý.

## Kết quả thực nghiệm trên DVWA

DVWA (Damn Vulnerable Web Application) là ứng dụng web được thiết kế cố ý chứa nhiều lỗ hổng bảo mật, dùng làm môi trường thực hành và thử nghiệm trong lĩnh vực bảo mật. Kết quả quét phát hiện tổng cộng 187 lần ghi nhận lỗ hổng thuộc 24 loại khác nhau, trong đó có 1 lỗ hổng mức Cao là SQL Injection tại trang cấu hình hệ thống, 64 lần ghi nhận mức Trung bình bao gồm thiếu Content Security Policy, Clickjacking, CSRF và Directory Browsing, 89 lần ghi nhận mức Thấp chủ yếu là rò rỉ thông tin phiên bản máy chủ, và 33 ghi nhận ở mức Thông tin. Con số 187 phản ánh tổng số lần ZAP phát hiện lỗ hổng trên từng endpoint riêng lẻ, không phải 187 loại lỗ hổng khác nhau, vì cùng một loại lỗ hổng có thể xuất hiện lặp lại trên nhiều trang của ứng dụng.

Kết quả quét chi tiết có trong thư mục demo của repository này.

## Cách chạy

Yêu cầu: Docker Desktop và Python 3.10 trở lên đã được cài đặt.

```bash
docker start zap
pip install -r requirements.txt
python app.py
```

Sau đó truy cập http://localhost:5000 trên trình duyệt.

## Cấu trúc mã nguồn

app.py là file chính của Flask, nhận yêu cầu từ giao diện và điều phối toàn bộ quy trình quét thông qua ZAP REST API. config.py chứa các thông số cấu hình. scanner/analyzer.py là phần lõi xử lý kết quả, tự động gán nhãn OWASP Top 10 2025, map CWE và WSTG cho từng lỗ hổng. Thư mục templates chứa giao diện web hiển thị kết quả.