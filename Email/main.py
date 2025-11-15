from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import os
# 2. 全局存储（替代Redis，基础题用）
from typing import Dict, Optional
import time
import threading
import uvicorn
# 3. 工具类模块（简化，无Redis）
import secrets
import bcrypt
# 邮件：基础用smt plib，进阶1用aiosmtplib
import smtplib
import aiosmtplib
from email.mime.text import MIMEText

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, EmailStr
from concurrent.futures import ThreadPoolExecutor  # 进阶1用

load_dotenv()

class Settings(BaseSettings):
    SMTP_SERVER: str = os.getenv("SMTP_SERVER")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT"))
    SENDER_EMAIL: str = os.getenv("SENDER_EMAIL")
    SENDER_AUTH_CODE: str = os.getenv("SENDER_AUTH_CODE")  # 不再硬编码！
    CODE_EXPIRE: int = int(os.getenv("CODE_EXPIRE"))
    CODE_LENGTH: int = int(os.getenv("CODE_LENGTH"))

settings = Settings()



# 存储：邮箱 -> {"code": str, "create_time": float}
CODE_STORAGE: Dict[str, Dict[str, str | float]] = {}
# 存储：邮箱 -> 最后请求验证码时间（防刷）
REQUEST_LIMIT: Dict[str, float] = {}
# 存储：邮箱 -> 加密后密码
USER_PASSWORD: Dict[str, bytes] = {}
# 线程锁（进阶方向1用，防并发读写冲突）
STORAGE_LOCK = threading.Lock()



# class EmailTool:
#     @staticmethod
#     def send_sync_email(to_email: str, subject: str, content: str) -> bool:
#         """基础题：同步发送邮件"""
#         try:
#             msg = MIMEText(content, "plain", "utf-8")
#             msg["From"] = f"密码重置中心<{settings.SENDER_EMAIL}>"
#             msg["To"] = to_email
#             msg["Subject"] =subject
#
#             with smtplib.SMTP_SSL(
#                 settings.SMTP_SERVER,
#                 settings.SMTP_PORT,
#                 timeout=30
#                 ) as server:
#                 server.login(settings.SENDER_EMAIL, settings.SENDER_AUTH_CODE)
#                 server.sendmail(settings.SENDER_EMAIL, to_email, msg.as_string())
#             return True
#         except Exception as e:
#             import traceback
#             print("接口邮件发送完整异常：\n" + traceback.format_exc())
#             return False
#
#
class EmailTool:
    @staticmethod
    def send_sync_email(to_email: str, subject: str, content: str) -> bool:
        try:
            # 构建邮件
            message = MIMEText(content, 'plain', 'utf-8')
            message['From'] = settings.SENDER_EMAIL
            message['To'] = to_email
            message['Subject'] = subject

            with smtplib.SMTP_SSL(
                    settings.SMTP_SERVER,
                    settings.SMTP_PORT,
                    timeout=60  # 保留60秒超时，应对网络波动
            ) as smtp:
            # 连接SMTP服务器并发送邮件
                smtp.login(settings.SENDER_EMAIL, settings.SENDER_AUTH_CODE)
            smtp.sendmail(
                from_addr=settings.SENDER_EMAIL,  # 发件人（与登录邮箱一致）
                to_addrs=to_email,  # 收件人（可传字符串或列表，如["a@qq.com", "b@qq.com"]）
                msg=message.as_string()  # 邮件内容（必须转成字符串，不能直接传message对象）
            )
            print(f"邮件发送成功，收件人: {to_email},内容：{content}")
            return True
        # finally:
        #         # 无论如何都尝试关闭连接，但不影响已发送成功的结果
        #     try:
        #         smtp.quit()
        #     except Exception as e:
        #         print(f"关闭SMTP连接时出现异常: {e}")
        #             # 不抛出异常，因为邮件已经发送成功
        except Exception as e:
            print(f"❌ 邮件发送失败详情：\n{e}")
            return False

    @staticmethod
    async def send_async_email(to_email: str, subject: str, content: str) -> bool:
        """进阶方向1：异步发送邮件"""
        try:
            msg = MIMEText(content, "html", "utf-8")
            msg["From"] = settings.SENDER_EMAIL
            msg["To"] =to_email
            msg["Subject"] =subject

            async with aiosmtplib.SMTP(
                    hostname=settings.SMTP_SERVER,
                    port=settings.SMTP_PORT,
                    use_tls=True,
                    timeout=30
            )as server:
                await server.login(settings.SENDER_EMAIL, settings.SENDER_AUTH_CODE)
                await server.sendmail(
                    settings.SENDER_EMAIL,
                    to_email,
                    msg.as_string()
                )
            return True
        except Exception as e:
            print(f"异步邮件失败：{e}")
            return False
class CodeTool:
    @staticmethod
    def generate_code() -> str:
        """生成6位随机验证码"""
        return str(secrets.randbelow(900000) + 100000)  # 100000~999999

    @staticmethod
    def save_code(email: str, code: str) -> bool:
        """保存验证码到字典"""
        with STORAGE_LOCK:  # 进阶1加锁，基础题可省略
            CODE_STORAGE[email] = {
                "code": code,
                "create_time": time.time()
            }
        return True

    @staticmethod
    def get_code(email: str) -> Optional[str]:
        """获取验证码，判断是否过期"""
        with STORAGE_LOCK:
            if email not in CODE_STORAGE:
                return None
            record = CODE_STORAGE[email]
            # 超过有效期，删除记录并返回None
            if time.time() - record["create_time"] > settings.CODE_EXPIRE:
                del CODE_STORAGE[email]
                return None
            return record["code"]


class PasswordTool:
    @staticmethod
    def hash_password(password: str) -> bytes:
        """密码哈希（bcrypt）"""
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    @staticmethod
    def verify_password(plain_password: str, hashed_password: bytes) -> bool:
        """密码验证"""
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password)


# 4. 接口路由模块


app = FastAPI(title="简化版密码重置API")
# 线程池（进阶1用，基础题可省略）
THREAD_POOL = ThreadPoolExecutor(max_workers=3)


# Pydantic模型
class RequestCodeSchema(BaseModel):
    email: EmailStr

class DoResetSchema(BaseModel):
    email: EmailStr
    code: str
    new_password: str


# 基础题接口1：请求验证码
@app.post("/api/reset-password/send-code")
async def request_reset_code(data: RequestCodeSchema):
    email = str(data.email)
    current_time = time.time()
    
    # 防刷逻辑
    if email in REQUEST_LIMIT and current_time - REQUEST_LIMIT[email] < 60:
        raise HTTPException(status_code=429, detail={"code": 429, "msg": "请勿频繁发送，1分钟后重试"})
    
    # 生成6位验证码
    code = CodeTool.generate_code()
    # 保存验证码到临时存储
    CodeTool.save_code(data.Email, code)
    
    # 构建邮件内容
    email_content = """您的验证码：{}，有效期2分钟""".format(code)
    try:
        # 发送邮件
        send_success = EmailTool.send_sync_email(email, "密码重置验证码", email_content)
        
        if not send_success:
            raise HTTPException(status_code=400, detail={"code": 400, "msg": "邮件发送失败，请检查邮箱配置"})
        
        # 更新最后请求时间
        REQUEST_LIMIT[email] = current_time
        return {"code": 200, "msg": f"验证码已发送至{email}"}
    except HTTPException:
        raise  # 重新抛出HTTPException，保留原始错误信息
    except Exception as e:
        print(f"接口邮件发送异常：{e}")
        raise HTTPException(status_code=400, detail={"code": 400, "msg": "邮件发送失败（接口内部异常）"})

#
# @app.post("/api/reset/request-code2")#异步进程
# async def request_reset_code(data: RequestCodeSchema):
#     email = str(data.email)
#     current_time = time.time()
#
#     # 防刷逻辑保留
#     if email in REQUEST_LIMIT and current_time - REQUEST_LIMIT[email] < 60:
#         raise HTTPException(status_code=429, detail={"code": 429, "msg": "请勿频繁发送，1分钟后重试"})
#
#     code = CodeTool.generate_code()
#     CodeTool.save_code(email, code)
#
#     # 极致简化邮件内容和主题
#     email_content = f"{code}"
#     send_success =await EmailTool.send_async_email(email, "密码重置验证码", email_content)
#     if not send_success:
#         raise HTTPException(status_code=400, detail={"code": 400, "msg": "邮件发送失败"})
#
#     REQUEST_LIMIT[email] = current_time
#     return {"code": 200, "msg": f"验证码已发送"}

# 基础题接口2：验证并重置密码
@app.post("/api/reset/do-reset")
async def do_reset_password(data: DoResetSchema):
    email = str(data.email)
    input_code = data.code
    new_password = data.new_password

    # 校验验证码
    stored_code = CodeTool.get_code(email)
    if not stored_code or stored_code != input_code:
        raise HTTPException(status_code=403, detail={"code": 403, "msg": "验证码过期或错误"})

    # 校验密码强度
    if len(new_password) < 8 or not (any(c.isupper() for c in new_password) and any(c.islower() for c in new_password)):
        raise HTTPException(status_code=400, detail={"code": 400, "msg": "新密码需≥8位且包含大小写字母"})

    # 加密并存储密码
    hashed_pwd = PasswordTool.hash_password(new_password)
    USER_PASSWORD[email] = hashed_pwd

    # 重置成功，删除验证码（避免重复使用）
    with STORAGE_LOCK:
        if email in CODE_STORAGE:
            del CODE_STORAGE[email]

    return {"code": 200, "msg": "密码重置成功"}


# 进阶方向2：CSRF漏洞接口
@app.get("/api/reset/trigger-harm")
async def trigger_harmful_email(email: EmailStr = Query(...)):
    """
    CSRF漏洞说明：
    1. 漏洞原因：未验证请求来源（无Referer/CSRF Token），攻击者可嵌入该链接到邮件/网页，用户点击即触发；
    2. 修复方案：添加CSRF Token（前端请求时获取Token，后端校验）或校验Referer头（仅允许信任域名请求）
    """
    # 发送有害邮件
    harmful_content = """
    <p>【紧急通知】您的账号因异常操作被冻结</p>
    <p>点击链接解冻：http://fake-phish.com（）</p>
    """
    EmailTool.send_sync_email(str(email), "账号风险通知", harmful_content)
    return {"code": 200, "msg": "操作执行完成"}


def check_email_config():
    """检查邮箱配置是否正确"""
    try:
        # 尝试连接SMTP服务器
        # 465直接用SMTP_SSL，无starttls()
        server = smtplib.SMTP_SSL(settings.SMTP_SERVER, settings.SMTP_PORT, timeout=30)
        server.login(settings.SENDER_EMAIL, settings.SENDER_AUTH_CODE)
        server.quit()
        print("✅ 465端口配置验证成功")
        return True
    except Exception as e:
        print(f"❌ 邮箱配置验证失败: {e}")
        return False

# 5. 主函数
if __name__ == "__main__":
    check_email_config()
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)