# CS253 项目 README

## 介绍
这是一个 CS253 课程的作业集合，包含多个作业目录和相关文件。

## 作业详细说明

### HW1 - 权限提升漏洞利用
**目标**: 在关闭 ASLR 的 Debian GNU/Linux 11 虚拟机中实现权限提升，从普通用户获取 root shell。

**文件结构**:
- [`disk.img`](hw1/disk.img) - 虚拟机磁盘镜像
- [`run_qemu.sh`](hw1/run_qemu.sh) - 启动 QEMU 虚拟机的脚本
- [`ssh_to_qemu.sh`](hw1/ssh_to_qemu.sh) - SSH 连接到虚拟机的脚本
- [`proj1_starter_code.tar.gz`](hw1/proj1_starter_code.tar.gz) - 项目启动代码
- [`readme.md`](hw1/readme.md) - 作业说明（中文）

**环境配置**:
- 用户名: user
- 密码: cs253
- 系统: Debian GNU/Linux 11 (bullseye)
- 安全特性: 已关闭 ASLR（地址随机化）

### HW2 - Spectre 攻击实现
**目标**: 实现 Spectre 攻击，通过 CPU 的推测执行漏洞泄露内存中的秘密数据。

**核心代码**: [`spec_skeleton.c`](hw2/spec_skeleton.c)
- 利用 CPU 分支预测器的训练机制
- 通过缓存侧信道攻击泄露数据
- 目标泄露字符串: "SUPER DONALD TRUMP TOP SECRET"

**技术要点**:
- 使用 `_mm_clflush()` 清除缓存
- 利用 `rdtsc` 指令测量访问时间
- 通过缓存命中/未命中判断数据
- 训练分支预测器绕过边界检查

**文件结构**:
- [`spec_skeleton.c`](hw2/spec_skeleton.c) - 主要攻击代码
- [`makefile`](hw2/makefile) - 编译配置
- [`requirements.txt`](hw2/requirements.txt) - 作业要求和说明

### HW3 - TLS 中间人攻击
**目标**: 实现 TLS 中间人攻击，拦截和修改 HTTPS 流量。

**核心组件**:
1. **伪造证书颁发机构**:
   - [`rogue-ca/`](hw3/Code/rogue-ca/) - 包含伪造的 CA 证书和私钥
   - [`forged-victim022.local.crt`](hw3/Code/rogue-ca/forged-victim022.local.crt) - 伪造的服务器证书

2. **MITM 代理脚本**: [`mitm-custom.py`](hw3/Code/mitm-custom.py)
   - 拦截 TLS 握手并注入伪造证书
   - 记录所有 HTTP 请求和响应
   - 在 HTML 页面中注入警告横幅

3. **测试网站**:
   - [`tls-mitm-lab/index.html`](hw3/tls-mitm-lab/index.html) - 模拟登录页面
   - [`tls-mitm-lab/capture.php`](hw3/tls-mitm-lab/capture.php) - 捕获登录凭据

**攻击流程**:
1. 客户端连接到 victim022.local
2. MITM 代理拦截 TLS 握手
3. 使用伪造证书与客户端建立连接
4. 同时与真实服务器建立连接
5. 转发并记录所有流量
6. 修改响应内容（注入警告横幅）

## 文件结构
- hw1/: 权限提升漏洞利用作业
- hw2/: Spectre 侧信道攻击作业
- hw3/: TLS 中间人攻击作业
- ssl/: SSL 配置和证书文件
- proj3_release.md: 项目3 发布文档
- proj3_release_zh.md: 项目3 发布文档（中文版）

## 使用说明
- **HW1**: 使用 [`run_qemu.sh`](hw1/run_qemu.sh) 启动虚拟机，然后开发权限提升漏洞利用
- **HW2**: 编译并运行 [`spec_skeleton.c`](hw2/spec_skeleton.c)，实现 Spectre 攻击
- **HW3**: 配置伪造 CA，运行 [`mitm-custom.py`](hw3/Code/mitm-custom.py) 进行中间人攻击

## 安全警告
这些作业仅用于教育目的，演示各种安全漏洞和攻击技术。请勿在生产环境或未经授权的系统上使用。

## 作者
Arno

## 更新时间
2025-12-29