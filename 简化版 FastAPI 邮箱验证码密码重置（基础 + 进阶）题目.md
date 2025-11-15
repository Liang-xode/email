# 简化版 FastAPI 邮箱验证码密码重置（基础 + 进阶）题目

## 一、题干

### （一）基础题（60 分）：实现邮箱验证码密码重置核心功能

基于 FastAPI 开发 “邮箱验证码密码重置” 基础系统，用**Python 内置字典**模拟存储（无需 Redis），提供 2 个核心接口：

1. **接口 1：请求重置验证码（POST /api/reset/request-code）**

- - 接收参数：用户邮箱（email: str，Pydantic 校验格式）

- - 功能逻辑：

① 生成 6 位随机数字验证码（secrets库实现，禁止硬编码）；

② 用全局字典存储 “邮箱 - 验证码 - 生成时间”（键：邮箱，值：{"code": 验证码, "create_time": 时间戳}），有效期 2 分钟；

③ 同步 SMTP 发送邮件（smtplib），内容含 “验证码（2 分钟有效）”+“输入验证码 + 新密码重置” 引导；

④ 响应：成功{"code":200,"msg":"验证码已发至[xxx@xxx.com](mailto:xxx@xxx.com)"}，失败（邮箱格式错 / SMTP 失败）{"code":400,"msg":"具体错误"}。

1. **接口 2：验证并重置密码（POST /api/reset/do-reset）**

- - 接收参数：邮箱（email: str）、验证码（code: str）、新密码（new_password: str）

- - 功能逻辑：

① 校验验证码：从字典取邮箱对应的记录，判断是否存在且当前时间-生成时间 < 120秒；

② 密码校验：长度≥8 位且包含大小写字母（不满足返回400）；

③ 重置：用另一个全局字典存储 “邮箱 - 加密后密码”（bcrypt哈希，禁止明文）；

④ 响应：成功{"code":200,"msg":"密码重置成功"}，验证码无效{"code":403,"msg":"验证码过期或错误"}。

### （二）进阶题（40 分，二选一）

#### 方向 1：性能优化（简化高并发）

基于基础题，用**异步 + 多线程**优化，支持 50 + 并发请求：

1. 技术要求：

- - 邮件发送改用异步aiosmtplib，避免单请求阻塞；

- - 字典存储加threading.Lock（线程锁），防止并发读写冲突；

- - 用concurrent.futures.ThreadPoolExecutor（线程池）处理验证码存储，提升效率。

1. 验证：用requests写简单并发脚本，10 秒内处理 50 个 “请求验证码” 请求，无超时 / 数据错乱。

#### 方向 2：CSRF 漏洞模拟

在基础题中添加 “恶意触发接口”，模拟漏洞：

1. **接口 3：恶意邮件触发（GET /api/reset/trigger-harm）**

- - 接收参数：目标邮箱（email: str，URL 参数传递，如?email=[victim@xxx.com](mailto:victim@xxx.com)）

- - 漏洞逻辑：

① 不验证请求来源（无 Referer/CSRF Token），收到 GET 请求就发 “有害邮件”（标题：【紧急】账号冻结，内容：“点击http://fake-phish.com解冻”）；

② 在接口 1 的重置邮件中，嵌入该接口链接（伪装 “补发送验证码”），用户点击即触发；

- - 分析：代码注释说明 “漏洞原因”+“1 种修复方案（如加 CSRF Token）”。

## 二、约束条件

1. 技术栈简化：

- - 框架：FastAPI + Pydantic（必选）；

- - 存储：仅用 Python 全局字典（禁止 Redis）；

- - 邮件：基础题smtplib（同步），进阶方向 1 用aiosmtplib（异步）；

- - 安全：secrets（验证码）、bcrypt（密码哈希）、threading（线程锁，进阶 1 用）。

1. 基础题防刷：同一邮箱 1 分钟内重复请求验证码，返回{"code":429,"msg":"1分钟后重试"}（用字典存 “邮箱 - 最后请求时间”）。

## 三、标准化代码框架

```
# 1. 配置模块（补充邮箱信息）
from pydantic import BaseSettings
class Settings(BaseSettings):
    SMTP_SERVER: str = "smtp.qq.com"  # QQ/163邮箱SMTP
    SMTP_PORT: int = 587  # TLS端口
    SENDER_EMAIL: str = "your-email@qq.com"  # 发送方邮箱
    SENDER_AUTH_CODE: str = "your-smtp-auth-code"  # SMTP授权码
    CODE_EXPIRE: int = 120  # 验证码有效期（秒）
    CODE_LENGTH: int = 6  # 6位验证码

settings = Settings()


# 2. 全局存储（替代Redis，基础题用）
from typing import Dict, Optional
import time
import threading

# 存储：邮箱 -> {"code": str, "create_time": float}
CODE_STORAGE: Dict[str, Dict[str, str | float]] = {}
# 存储：邮箱 -> 最后请求验证码时间（防刷）
REQUEST_LIMIT: Dict[str, float] = {}
# 存储：邮箱 -> 加密后密码
USER_PASSWORD: Dict[str, bytes] = {}
# 线程锁（进阶方向1用，防并发读写冲突）
STORAGE_LOCK = threading.Lock()


# 3. 工具类模块（简化，无Redis）
import secrets
import bcrypt
# 邮件：基础用smtplib，进阶1用aiosmtplib
import smtplib
import aiosmtplib
from email.mime.text import MIMEText
from email.header import Header

class EmailTool:
    @staticmethod
    def send_sync_email(to_email: str, subject: str, content: str) -> bool:
        """基础题：同步发送邮件"""
        try:
            msg = MIMEText(content, "html", "utf-8")
            msg["From"] = Header(f"密码重置中心<{settings.SENDER_EMAIL}>", "utf-8")
            msg["To"] = Header(to_email, "utf-8")
            msg["Subject"] = Header(subject, "utf-8")
            
            with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
                server.starttls()
                server.login(settings.SENDER_EMAIL, settings.SENDER_AUTH_CODE)
                server.sendmail(settings.SENDER_EMAIL, to_email, msg.as_string())
            return True
        except Exception as e:
            print(f"邮件发送失败：{e}")
            return False

    @staticmethod
    async def send_async_email(to_email: str, subject: str, content: str) -> bool:
        """进阶方向1：异步发送邮件"""
        try:
            msg = MIMEText(content, "html", "utf-8")
            msg["From"] = Header(f"密码重置中心<{settings.SENDER_EMAIL}>", "utf-8")
            msg["To"] = Header(to_email, "utf-8")
            msg["Subject"] = Header(subject, "utf-8")
            
            async with aiosmtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
                await server.starttls()
                await server.login(settings.SENDER_EMAIL, settings.SENDER_AUTH_CODE)
                await server.send_message(msg)
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
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, EmailStr
from concurrent.futures import ThreadPoolExecutor  # 进阶1用

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
@app.post("/api/reset/request-code")
async def request_reset_code(data: RequestCodeSchema):
    email = data.email
    current_time = time.time()

    # 防刷：1分钟内重复请求
    if email in REQUEST_LIMIT and current_time - REQUEST_LIMIT[email] < 60:
        raise HTTPException(status_code=429, detail={"code":429,"msg":"请勿频繁发送，1分钟后重试"})

    # 生成+保存验证码
    code = CodeTool.generate_code()
    CodeTool.save_code(email, code)

    # 发送邮件（基础题同步，进阶1可改用异步+线程池）
    email_content = f"""
    <p>您的密码重置验证码：<strong>{code}</strong></p>
    <p>有效期2分钟，请输入验证码和新密码完成重置</p>
    """
    send_success = EmailTool.send_sync_email(email, "密码重置验证码", email_content)
    if not send_success:
        raise HTTPException(status_code=400, detail={"code":400,"msg":"邮件发送失败，请检查邮箱配置"})

    # 更新最后请求时间
    REQUEST_LIMIT[email] = current_time
    return {"code":200,"msg":f"验证码已发送至{email}"}

# 基础题接口2：验证并重置密码
@app.post("/api/reset/do-reset")
async def do_reset_password(data: DoResetSchema):
    email = data.email
    input_code = data.code
    new_password = data.new_password

    # 校验验证码
    stored_code = CodeTool.get_code(email)
    if not stored_code or stored_code != input_code:
        raise HTTPException(status_code=403, detail={"code":403,"msg":"验证码过期或错误"})

    # 校验密码强度
    if len(new_password) < 8 or not (any(c.isupper() for c in new_password) and any(c.islower() for c in new_password)):
        raise HTTPException(status_code=400, detail={"code":400,"msg":"新密码需≥8位且包含大小写字母"})

    # 加密并存储密码
    hashed_pwd = PasswordTool.hash_password(new_password)
    USER_PASSWORD[email] = hashed_pwd

    # 重置成功，删除验证码（避免重复使用）
    with STORAGE_LOCK:
        if email in CODE_STORAGE:
            del CODE_STORAGE[email]

    return {"code":200,"msg":"密码重置成功"}

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
    <p>点击链接解冻：http://fake-phish.com（伪造钓鱼链接）</p>
    """
    EmailTool.send_sync_email(email, "账号风险通知", harmful_content)
    return {"code":200,"msg":"操作执行完成"}


# 5. 主函数
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
```

## 四、解答提示

### 1. 基础题关键提示

- **字典过期处理**：CodeTool.get_code中，通过time.time() - 生成时间判断是否超过 120 秒，过期则删除字典记录；

- **防刷逻辑**：REQUEST_LIMIT字典存 “邮箱 - 最后请求时间”，请求时先判断间隔是否小于 60 秒；

- **邮件内容**：用 HTML 标签（<strong>）突出验证码，提升用户可读性，示例：

```
content = f"<p>验证码：<strong>{code}</strong>（2分钟有效）</p><p>请用验证码+新密码重置</p>"
```

### 2. 进阶方向 1（性能优化）提示

- **异步邮件**：替换send_sync_email为send_async_email，接口用async def，调用时直接await EmailTool.send_async_email(...)；

- **线程锁作用**：STORAGE_LOCK确保多线程同时读写CODE_STORAGE时不报错（如 A 线程写时 B 线程读）；

- **并发测试脚本示例**（用requests）：

```
import requests
import concurrent.futures

def test_request_code():
    url = "http://localhost:8000/api/reset/request-code"
    data = {"email": "test_concurrent@example.com"}
    response = requests.post(url, json=data)
    return response.status_code

# 50个并发请求
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    results = [executor.submit(test_request_code) for _ in range(50)]
    for future in results:
        print(f"响应码：{future.result()}")
```

### 3. 进阶方向 2（CSRF 漏洞）提示

- **漏洞触发场景**：在接口 1 的邮件中添加<a href="http://localhost:8000/api/reset/trigger-harm?email={email}">未收到验证码？点击补发</a>，用户点击后即发送有害邮件；

- **修复方案代码示例（CSRF Token）**：

```
# 新增Token存储字典
CSRF_TOKENS: Dict[str, str] = {}

# 接口：获取CSRF Token
@app.get("/api/get-csrf-token")
async def get_csrf_token(email: EmailStr):
    token = secrets.token_urlsafe(16)
    CSRF_TOKENS[email] = token
    return {"csrf_token": token}

# 修复漏洞接口：添加Token校验
@app.get("/api/reset/trigger-harm")
async def trigger_harmful_email(email: EmailStr, csrf_token: str = Query(...)):
    if CSRF_TOKENS.get(email) != csrf_token:
        raise HTTPException(status_code=403, detail="CSRF Token无效")
    # 后续发送邮件逻辑...
```
