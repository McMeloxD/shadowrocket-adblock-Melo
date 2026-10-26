#!/usr/bin/env python3
"""通过 SMTP over TLS 发送 Actions 失败通知；凭据仅从环境变量读取。"""
import os
from pathlib import Path
import smtplib
import ssl
import sys
from email.message import EmailMessage


REPORT = Path(__file__).resolve().parent / "notification-report" / "security-report.txt"


def main():
    required = ("MAIL_SERVER", "MAIL_USERNAME", "MAIL_PASSWORD", "MAIL_TO")
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        print("::error::邮件通知未配置，缺少 GitHub Secrets: " + ", ".join(missing), file=sys.stderr)
        return 1

    try:
        port = int(os.environ.get("MAIL_PORT") or "465")
        if not 1 <= port <= 65535:
            raise ValueError("invalid port")
        repository = os.environ["GITHUB_REPOSITORY"]
        run_url = (f"{os.environ['GITHUB_SERVER_URL']}/{repository}"
                   f"/actions/runs/{os.environ['GITHUB_RUN_ID']}")
        build = os.environ["BUILD_RESULT"]
        publish = os.environ["PUBLISH_RESULT"]
        message = EmailMessage()
        message["Subject"] = f"[去广告更新失败] {repository}"
        message["From"] = os.environ["MAIL_USERNAME"]
        message["To"] = os.environ["MAIL_TO"]
        body = (f"自动更新未正常完成，请检查本次 Actions 运行。\n\n"
                f"构建/安全校验: {build}\n发布: {publish}\n"
                f"运行详情: {run_url}\n\n")
        if build == "failure":
            body += "构建失败，本次产物未交付发布，继续使用上一版模块。\n"
        else:
            body += "发布任务失败，请通过运行详情核实远端提交状态。\n"
        if REPORT.is_file():
            report = REPORT.read_text(encoding="utf-8")
            message.set_content(body + "\n安全报告:\n" + report)
            message.add_attachment(report, subtype="plain", filename="security-report.txt")
        else:
            message.set_content(body + "\n未生成或未能获取安全报告，请查看运行日志。\n")

        with smtplib.SMTP_SSL(os.environ["MAIL_SERVER"], port, timeout=30,
                              context=ssl.create_default_context()) as smtp:
            smtp.login(os.environ["MAIL_USERNAME"], os.environ["MAIL_PASSWORD"])
            smtp.send_message(message)
    except Exception as error:  # noqa: BLE001
        # SMTP 错误可能携带地址或服务端响应，日志只记录类型，避免输出凭据。
        print(f"::error::邮件发送失败（{type(error).__name__}），请检查邮件 Secrets、"
              "SMTP over TLS 端口和邮箱授权码。", file=sys.stderr)
        return 1
    print("失败通知已提交给邮件服务器。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
