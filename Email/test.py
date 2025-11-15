# test_587.py
import smtplib
from email.mime.text import MIMEText
from email.header import Header
import socket
import sys

# 配置 - 使用465端口和SMTP_SSL，与main.py保持一致
SMTP_SERVER = "smtp.qq.com"
SMTP_PORT = 465  # 使用465端口SSL连接
SENDER_EMAIL = "3174330169@qq.com"
# 使用与main.py中相同的授权码
SENDER_AUTH_CODE = "rdynggeuarvqdgbd"  # 从main.py复制的授权码
TO_EMAIL = "2410457599@qq.com"  # 填你要测试的邮箱

def test_587_send():
    try:
        print(f"正在初始化邮件内容...")
        msg = MIMEText("测试邮件内容", "plain", "utf-8")
        msg["From"] = SENDER_EMAIL
        msg["To"] = TO_EMAIL
        msg["Subject"] = Header("测试邮件", "utf-8").encode()
        
        print(f"正在连接SMTP服务器: {SMTP_SERVER}:{SMTP_PORT} (SSL连接)...")
        # 使用SMTP_SSL直接连接
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, timeout=60)
        server.set_debuglevel(1)  # 启用调试输出
        
        try:
            print(f"正在登录邮箱: {SENDER_EMAIL}...")
            print(f"提示：当前使用的授权码前几位: {SENDER_AUTH_CODE[:5]}...")
            server.login(SENDER_EMAIL, SENDER_AUTH_CODE)
            
            print(f"正在发送邮件到: {TO_EMAIL}...")
            server.sendmail(SENDER_EMAIL, TO_EMAIL, msg.as_string())
            print("✅ 465端口SSL连接发送成功！")
            return True
        finally:
            print("正在关闭SMTP连接...")
            try:
                server.quit()
            except Exception as e:
                print(f"关闭连接时发生错误（可忽略）: {e}")
                pass
            
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ 465端口SSL连接报错：邮箱认证失败！错误码: {e.smtp_code}, 错误信息: {e.smtp_error}")
        print("注意：QQ邮箱需要使用授权码而非密码进行登录。")
        print("请检查：1. SMTP服务是否已开启 2. 授权码是否正确 3. 账号是否异常")
        print("获取QQ邮箱授权码方法：设置 -> 账户 -> POP3/IMAP/SMTP/Exchange/CardDAV/CalDAV服务")
        import traceback
        traceback.print_exc()
    except smtplib.SMTPServerDisconnected:
        print("❌ 465端口SSL连接报错：SMTP服务器连接意外断开！")
        print("可能的原因：")
        print("1. 网络连接问题")
        print("2. SMTP服务器配置错误")
        print("3. 防火墙阻止")
        print("4. 授权码过期或不正确")
        print("5. 登录频率限制")
        import traceback
        traceback.print_exc()
    except socket.error as e:
        print(f"❌ 465端口SSL连接报错：网络连接错误 - {str(e)}")
        import traceback
        traceback.print_exc()
    except Exception as e:
        print(f"❌ 465端口SSL连接报错：{str(e)}")
        import traceback
        traceback.print_exc()
    return False

if __name__ == "__main__":
    print("=== 开始测试SMTP邮件发送（SSL连接）===")
    print("当前配置:")
    print(f"- SMTP服务器: {SMTP_SERVER}")
    print(f"- 端口: {SMTP_PORT}")
    print(f"- 发件人: {SENDER_EMAIL}")
    print(f"- 收件人: {TO_EMAIL}")
    
    success = test_587_send()
    print("=== 测试结束 ===")
    
    if not success:
        print("\n提示：")
        print("1. 请确保QQ邮箱已开启SMTP服务")
        print("2. 请确保使用的是正确的授权码（非密码）")
        print("3. 如果授权码已过期，请重新生成")
        print("4. 检查网络连接和防火墙设置")
    
    # 根据发送结果设置退出码
    sys.exit(0 if success else 1)