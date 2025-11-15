import smtplib
from email.mime.text import MIMEText
from email.header import Header

# 从main.py复制的配置
SENDER_EMAIL = "3174330169@qq.com"
SENDER_AUTH_CODE = "rdynggeuarvqdgbd"  # 已更新为成功的授权码
TO_EMAIL = "2410457599@qq.com"  # 测试邮箱

print("=== 测试main.py中的邮箱配置 ===")
print(f"使用配置：{SENDER_EMAIL}, 授权码：{SENDER_AUTH_CODE[:5]}...")

try:
    msg = MIMEText("这是来自main.py配置的测试邮件", "plain", "utf-8")
    msg["From"] = SENDER_EMAIL
    msg["To"] = TO_EMAIL
    msg["Subject"] = Header("main.py测试", "utf-8").encode()
    
    # 使用465端口SSL连接
    with smtplib.SMTP_SSL("smtp.qq.com", 465, timeout=60) as server:
        server.set_debuglevel(1)  # 启用调试输出
        server.login(SENDER_EMAIL, SENDER_AUTH_CODE)
        server.sendmail(SENDER_EMAIL, TO_EMAIL, msg.as_string())
    print("✅ 邮件发送成功！")
except Exception as e:
    print(f"❌ 邮件发送失败: {str(e)}")
    import traceback
    traceback.print_exc()
