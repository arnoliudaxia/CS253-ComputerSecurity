# CS 253: 网络安全 - 项目 3: TLS 拦截和中间人攻击
**教授：** Yuan Xiao
**学期：** 2025 年秋季

## 1. 实验室概述

这个动手项目将指导您建立一个带有 TLS 的受害网站，然后执行中间人 (MitM) 攻击来拦截 HTTPS 流量。您将在隔离环境中使用虚拟机或容器工作。不要在您的原生操作系统上尝试这样做，因为它可能会破坏您的整个网络堆栈。

请注意，这个项目设计得很具挑战性。您不必完成所有内容，但在截止日期前尽可能多地完成。这个项目将根据您完成的步骤进行评分。总共有 15 分，每个步骤的确切分数如下所示。

本指南以 MD 格式提供给您，以便您轻松复制粘贴提供的代码和命令。您可以选择理论上任何带有网页浏览器和网络功能的虚拟机来完成项目，但 FYI 测试环境是 VMware Workstation 运行 Ubuntu 20.04 Desktop。

不要复制他人的代码来完成作业。这不值得。任何发现的作弊将导致 (1) 本项目零分，以及 (2) 本课程最终成绩降低一级。

## 2. 提交要求

这个项目要求您提交一个压缩包到 Gradescope，包括以下内容（取决于您在截止日期前完成多少）：

1. **里程碑截图：**
   - 自签名证书的浏览器警告
   - 使用恶意 CA 的成功 HTTPS 连接
   - mitmproxy 拦截登录凭据

2. **实验室报告：**
   - 列出您完成的步骤以及相应的截图

3. **代码：**
   - 所有配置文件
   - 自定义脚本
   - 证书文件（私钥已删除）

## 3. 初始设置

首先，创建您的隔离实验室环境：

```bash
# 创建项目目录
mkdir tls-mitm-lab && cd tls-mitm-lab

# 更新系统包
sudo apt update && sudo apt upgrade -y

# 安装所需包
sudo apt install -y apache2 openssl mitmproxy python3-pip
```

## 4. 第 1 部分：使用自签名证书部署受害网站

### 步骤 1.1：创建受害网站 (1 分)

创建网页根目录和一个简单的登录页面。本文档中的所有 **022** 代表您学生 ID 的最后三位，用于识别不同学生的作业。

```bash
sudo mkdir -p /var/www/victim022.local/html
sudo chown -R $USER:$USER /var/www/victim022.local/html
sudo chmod -R 755 /var/www/victim022.local
```

**文件：`/var/www/victim022.local/html/index.html`**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Login - Victim Local</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 500px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .login-form {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            background-color: #4CAF50;
            color: white;
            padding: 12px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            width: 100%;
            font-size: 16px;
        }
        button:hover {
            background-color: #45a049;
        }
        .alert {
            padding: 10px;
            background-color: #f44336;
            color: white;
            border-radius: 4px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="login-form">
        <h2>安全用户登录</h2>
        <div class="alert">
            <strong>警告：</strong> 这是一个用于安全教育的测试站点。
        </div>

        <form id="loginForm">
            <div class="form-group">
                <label for="username">用户名：</label>
                <input type="text" id="username" name="username" required>
            </div>

            <div class="form-group">
                <label for="password">密码：</label>
                <input type="password" id="password" name="password" required>
            </div>

            <button type="submit">登录</button>
        </form>

        <div id="result" style="margin-top: 20px;"></div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();

            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            // 模拟表单提交
            const resultDiv = document.getElementById('result');
            resultDiv.innerHTML = `
                <div style="background-color: #d4edda; color: #155724; padding: 10px; border-radius: 4px;">
                    登录尝试已记录：<br>
                    用户名：${username}<br>
                    密码：${password}
                </div>
            `;

            // 在真实场景中，这将被发送到服务器
            console.log('登录尝试：', { username, password });
            fetch("/capture", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password })
            });
        });
    </script>
</body>
</html>
```

**文件：`/var/www/victim022.local/html/capture.php`**
```php
<?php
// 只是静默接受 POST
http_response_code(200);
?>
```

### 步骤 1.2：生成自签名证书 (2 分)

创建并导航到证书目录：

```bash
mkdir ~/certs && cd ~/certs
```
在其中，
1. 生成一个 2048 位 RSA 私钥，名为 **victim022.local.key**。

2. 生成一个自签名证书 (**victim022.local.crt**)。证书必须具有：
   - 国家、省、市、组织（任意）
   - 通用名称 (CN) = victim022.local

3. 设置适当权限，以便只有所有者可以读取密钥。

**提示：** 命令将使用 *openssl genrsa, openssl req -new -x509* 等。

### 步骤 1.3：为 HTTPS 配置 Apache (2 分)

创建 **/etc/apache2/sites-available/victim022.local.conf**

您的 VirtualHost 应该：

1. 监听端口 443

2. 具有：
```apache
    ServerName victim022.local
    DocumentRoot /var/www/victim022.local/html
```

3. 启用 TLS：
```apache
    SSLEngine on
    SSLCertificateFile <path to victim022.local.crt>
    SSLCertificateKeyFile <path to victim022.local.key>
```

4. 包含三个安全头：
```apache
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
```

5. 使用 *Alias* 处理 */capture*。

6. 记录访问和错误日志：
```apache
    ErrorLog ${APACHE_LOG_DIR}/victim022.local_error.log
    CustomLog ${APACHE_LOG_DIR}/victim022.local_access.log combined
```
7. HTTP → HTTPS 重定向

   - 创建一个单独的端口-80 VirtualHost，将永久重定向到 https://victim022.local 。

启用站点和所需模块：

```bash
# 启用 Apache 模块
sudo a2enmod ssl
sudo a2enmod headers
sudo a2enmod rewrite

# 启用受害站点
sudo a2ensite victim022.local.conf

# 禁用默认站点
sudo a2dissite 000-default.conf

# 重启 Apache
sudo systemctl restart apache2
```

### 步骤 1.4：配置本地 DNS (0.5 分)

将 victim022.local 添加到您的 hosts 文件：

```bash
echo "127.0.0.1 victim022.local" | sudo tee -a /etc/hosts
```

### 步骤 1.5：测试受害网站 (0.5 分)

```bash
# 测试 Apache 配置
sudo apache2ctl configtest

# 检查 Apache 是否正在运行
sudo systemctl status apache2

# 测试 HTTP 到 HTTPS 重定向
curl -I http://victim022.local

# 测试 HTTPS（不使用 -k 标志，它将失败验证 - 这是预期的）
curl -k https://victim022.local
```

在浏览器中打开 https://victim022.local 并 **记录** 安全警告。

## 5. 第 2 部分：中间人攻击

### 步骤 2.1：成为恶意证书颁发机构 (1 分)

为您的恶意 CA 创建目录：

```bash
mkdir ~/rogue-ca && cd ~/rogue-ca
```

在其中，
1. 生成一个 4096 位 CA 私钥 **rogue-ca.key**

2. 生成一个根 CA 证书 **rogue-ca.crt**。
   - CN 和 O 必须清楚表明恶意意图。
   - 例如，**O=Evil Corp, CN=Evil Root CA**

3. 为 CA 操作创建必要的目录和文件

### 步骤 2.2：将恶意 CA 安装为受信任 (1 分)
将 **rogue-ca.crt** 安装到您的操作系统信任存储中。

**在 Linux 上：**
```bash
# 将 CA 证书复制到系统信任存储
sudo cp rogue-ca.crt /usr/local/share/ca-certificates/rogue-ca.crt
sudo update-ca-certificates

# 验证安装
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt rogue-ca.crt
```

**在 macOS 上：**
```bash
# 将 CA 证书导入到 Keychain
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain rogue-ca.crt
```

**在 Windows 上：**
- 将 `rogue-ca.crt` 复制到 Windows
- 运行 `certmgr.msc`
- 导入到 "受信任的根证书颁发机构"

### 步骤 2.3：为受害者生成伪造证书 (2 分)

为 victim022.local 创建证书签名请求 (CSR)。您必须：

1. 生成一个私钥 **forged-victim022.local.key**。

2. 生成一个 CSR **forged-victim022.local.csr**，CN = victim022.local。

3. 创建一个扩展文件，包含：
   - subjectAltName = DNS:victim022.local

4. 使用您的 **恶意 CA**（不是 openssl 默认 CA）签署 CSR。

5. 使用以下命令验证伪造证书：
   ```bash
   openssl verify -CAfile rogue-ca.crt forged-victim022.local.crt
   ```

### 步骤 2.4：配置 mitmproxy (2 分)

创建一个自定义 mitmproxy 脚本以使用我们的伪造证书：

**文件：`~/mitm-custom.py`**
```python
from mitmproxy import http, ctx

class CertificateForger:
    def __init__(self):
        # TODO: 在此处放置您的证书或通过参数传递。
        pass

    def tls_clienthello(data: tls.ClientHello):
        """
        TODO: 如果是 victim022.local，跳过 mitmproxy 对上游 Apache 证书的验证，
        并使用我们的伪造证书与客户端通信。
        您也可以使用其他脚本或参数来完成此操作；
        此函数不是必需的。
        """
        pass

    def request(self, flow: http.HTTPFlow) -> None:
        """
        此方法在客户端发送 HTTP(S) 请求时运行。

        - 使用 ctx.log.info 记录请求 URL。
        - 记录请求头。使用 flow.request.headers 访问头
        - 如果请求有主体，解码并记录它。
        - 这些日志帮助您检查拦截的流量。
        """
        # 记录所有请求
        ctx.log.info(f"拦截的请求到：{flow.request.pretty_url}")
        ctx.log.info(f"头：{flow.request.headers}")
        if flow.request.content:
            ctx.log.info(f"主体：{flow.request.content.decode()}")

    def response(self, flow: http.HTTPFlow) -> None:
        """
        此方法在 mitmproxy 从服务器接收响应时运行。

        要求：
        - 如果响应包含 HTML 内容：
            * 检查 HTML 是否有 <body> 标签。
            * 在 HTML 主体内注入一个可见警告横幅（WARNING HTML），
              表明流量已被拦截。
            * 将修改后的内容替换到流响应中。

        这模仿了攻击者如何篡改服务器响应。

        提示：
        - 响应状态：flow.response.status_code
        - 响应主体：flow.response.content
        - 使用 .decode() 将字节转换为文本
        - 搜索 "<body>"
        - 对字符串执行 .replace()
        - 在分配给 flow.response.content 之前编码回字节

        """

        # 记录所有响应
        ctx.log.info(f"从拦截的响应：{flow.request.pretty_url}")
        ctx.log.info(f"状态：{flow.response.status_code}")
        # 此 HTML 片段必须在 <body> 标签后立即注入。
        WARNING_HTML = """
        <!-- 被 MITM PROXY 拦截 -->
        <div style='background:red;color:white;
                    padding:10px;
                    text-align:center;
                    font-weight:bold;
                    font-size:18px;'>
            安全警告：流量已被拦截
        </div>
        """
        pass  # TODO: 将横幅注入 HTML 内容以显示我们拦截了它

# 使用 mitmproxy 注册插件
addons = [CertificateForger()]

```

### 步骤 2.5：设置流量重定向 (2 分)

配置 iptables 来重定向流量：
1. 启用 IP 转发

2. 清除现有规则
   ```bash
   sudo iptables -F
   sudo iptables -t nat -F
   ```
3. 将 HTTP 流量重定向到 mitmproxy（端口 8080）

4. 将 HTTPS 流量重定向到 mitmproxy（端口 8080）

5. （可选）保存 iptables 规则（方法因发行版而异）

**提示：** 由于我们的流量来自本地机器，规则设置需要考虑循环问题。参考此 [文档](https://docs.mitmproxy.org/stable/howto/transparent/) 可能会有帮助。

### 步骤 2.6：启动 mitmproxy 并测试拦截 (1 分)

使用不同接口启动 mitmproxy。请注意，以下命令仅供参考。您可以更改启动参数配置（如 --certs、ssl_keyfile 等），但您 **必须使用透明** 模式。

**选项 1：命令行界面**
```bash
mitmproxy --mode transparent --showhost --set confdir=~/rogue-ca -s ~/mitm-custom.py
```

**选项 2：网页界面**
```bash
mitmweb --mode transparent --showhost --set confdir=~/rogue-ca -s ~/mitm-custom.py
```

**选项 3：简单代理模式**
```bash
mitmdump --mode transparent -w traffic_dump.mitm
```

现在测试拦截：

1. 打开新终端并测试拦截：
```bash
# 测试不感知代理
curl -v https://victim022.local
```

2. 在浏览器中清除站点设置、缓存项。然后打开 Firefox 并配置为不使用代理：
```bash
# 启动 Firefox 不使用系统代理
env http_proxy= https_proxy= HTTP_PROXY= HTTPS_PROXY= \
firefox --no-remote --proxy-server="direct://" https://victim022.local
```

3. 在受害站点上执行登录并在 mitmproxy 中观察流量。

## 6. 验证和测试脚本

创建验证脚本来测试您的设置（帮助您测试和调试）：

**文件：`test_mitm.py`**
```python
#!/usr/bin/env python3
import requests
import urllib3
import sys

# 禁用 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_victim_site():
    """测试直接连接到受害站点"""
    try:
        response = requests.get('https://victim022.local', verify=False, timeout=5)
        print(f"✓ 受害站点可访问：状态 {response.status_code}")
        return True
    except Exception as e:
        print(f"✗ 受害站点不可访问：{e}")
        return False

def test_mitm_interception():
    """测试流量是否被拦截"""
    try:
        # 此请求应通过 mitmproxy
        response = requests.get('https://victim022.local', verify=False, timeout=5)

        if 'INTERCEPTED' in response.text:
            print("✓ 流量拦截已确认")
            return True
        else:
            print("✗ 流量未拦截 - mitmproxy 未工作")
            return False
    except Exception as e:
        print(f"✗ 拦截测试失败：{e}")
        return False

if __name__ == "__main__":
    print("测试 MITM 设置...")
    print("=" * 40)

    victim_ok = test_victim_site()
    mitm_ok = test_mitm_interception()

    print("=" * 40)
    if victim_ok and mitm_ok:
        print("✓ 所有测试通过！MITM 设置正常工作。")
        sys.exit(0)
    else:
        print("✗ 某些测试失败。请检查您的设置。")
        sys.exit(1)
```

使其可执行并运行：
```bash
chmod +x test_mitm.py
python3 test_mitm.py
```

## 7. 清理脚本

此脚本是一个紧急助手，如果您搞乱了设置并想重新开始：

**文件：`cleanup.sh`**
```bash
#!/bin/bash
echo "清理 MITM 实验室..."

# 移除 iptables 规则
sudo iptables -t nat -F
sudo iptables -F

# 禁用 Apache 站点
sudo a2dissite victim022.local.conf
sudo a2ensite 000-default.conf
sudo systemctl restart apache2

# 从 hosts 文件中移除
sudo sed -i '/victim022.local/d' /etc/hosts

# 从信任存储中移除恶意 CA
sudo rm -f /usr/local/share/ca-certificates/rogue-ca.crt
sudo update-ca-certificates

echo "清理完成。请记住重启您的浏览器。"