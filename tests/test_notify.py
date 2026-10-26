import contextlib
import io
import os
from pathlib import Path
import smtplib
import tempfile
import unittest
from unittest.mock import patch

import notify


class NotifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.report = Path(self.temp.name) / "security-report.txt"
        self.environment = {
            "MAIL_SERVER": "smtp.example.com",
            "MAIL_USERNAME": "sender@example.com",
            "MAIL_PASSWORD": "private-app-password",
            "MAIL_TO": "owner@example.com",
            "GITHUB_REPOSITORY": "owner/adblock",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_RUN_ID": "123",
            "BUILD_RESULT": "failure",
            "PUBLISH_RESULT": "skipped",
        }

    def run_notify(self, smtp_error=None):
        output = io.StringIO()
        with patch.dict(os.environ, self.environment, clear=True), patch.object(notify, "REPORT", self.report):
            with patch.object(notify.smtplib, "SMTP_SSL") as connection:
                smtp = connection.return_value.__enter__.return_value
                smtp.send_message.side_effect = smtp_error
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    code = notify.main()
        return code, connection, smtp, output.getvalue()

    def test_security_failure_includes_report_and_uses_configured_recipient(self):
        self.report.write_text("风险: 脚本 SHA256 变化", encoding="utf-8")
        code, connection, smtp, _ = self.run_notify()
        self.assertEqual(0, code)
        self.assertEqual(("smtp.example.com", 465), connection.call_args.args)
        tls = connection.call_args.kwargs["context"]
        self.assertTrue(tls.check_hostname)
        smtp.login.assert_called_once_with("sender@example.com", "private-app-password")
        message = smtp.send_message.call_args.args[0]
        self.assertEqual("owner@example.com", message["To"])
        self.assertIn("https://github.com/owner/adblock/actions/runs/123", message.get_body().get_content())
        self.assertIn("脚本 SHA256", message.get_body().get_content())
        attachment = next(message.iter_attachments())
        self.assertEqual("security-report.txt", attachment.get_filename())
        self.assertIn("脚本 SHA256", attachment.get_content())

    def test_missing_report_still_sends_failure_email(self):
        code, _, smtp, _ = self.run_notify()
        self.assertEqual(0, code)
        message = smtp.send_message.call_args.args[0]
        self.assertIn("未生成或未能获取安全报告", message.get_content())

    def test_publish_failure_does_not_claim_remote_is_unchanged(self):
        self.environment.update(BUILD_RESULT="success", PUBLISH_RESULT="failure", MAIL_PORT="2465")
        code, connection, smtp, _ = self.run_notify()
        self.assertEqual(0, code)
        self.assertEqual(2465, connection.call_args.args[1])
        body = smtp.send_message.call_args.args[0].get_content()
        self.assertIn("核实远端提交状态", body)
        self.assertNotIn("继续使用上一版", body)

    def test_missing_secrets_fail_without_connecting(self):
        for key in ("MAIL_SERVER", "MAIL_USERNAME", "MAIL_PASSWORD", "MAIL_TO"):
            with self.subTest(key=key):
                original = self.environment.pop(key)
                try:
                    code, connection, _, output = self.run_notify()
                    self.assertEqual(1, code)
                    connection.assert_not_called()
                    self.assertIn(key, output)
                    self.assertNotIn("private-app-password", output)
                finally:
                    self.environment[key] = original

    def test_invalid_port_fails_before_connecting(self):
        for port in ("invalid", "0", "65536"):
            with self.subTest(port=port):
                self.environment["MAIL_PORT"] = port
                code, connection, _, _ = self.run_notify()
                self.assertEqual(1, code)
                connection.assert_not_called()

    def test_smtp_failure_is_visible_without_leaking_response_or_password(self):
        error = smtplib.SMTPAuthenticationError(535, b"private-app-password rejected")
        code, _, _, output = self.run_notify(error)
        self.assertEqual(1, code)
        self.assertIn("SMTPAuthenticationError", output)
        self.assertNotIn("private-app-password", output)


if __name__ == "__main__":
    unittest.main()
