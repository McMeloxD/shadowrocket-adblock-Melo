import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import merge


SOURCE = "https://raw.githubusercontent.com/example/modules/main/one.sgmodule"
SECOND_SOURCE = "https://raw.githubusercontent.com/example/modules/main/two.sgmodule"
SCRIPT = "https://raw.githubusercontent.com/example/scripts/main/adblock.js"
BODY = "$done({});"
RULES = [f"DOMAIN,ad{i}.example.com,REJECT" for i in range(10)]
SCRIPT_LINES = [f"ad{i} = type=http-response, script-path={SCRIPT}" for i in range(5)]
HOSTS = [f"api{i}.example.com" for i in range(5)]


def module_text(rules=RULES, scripts=SCRIPT_LINES, hosts=HOSTS):
    return ("[Rule]\n" + "\n".join(rules) + "\n[Script]\n" + "\n".join(scripts)
            + "\n[MITM]\nhostname = %APPEND% " + ", ".join(hosts))


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        paths = {name: str(self.root / filename) for name, filename in {
            "SOURCES_FILE": "sources.txt", "BASELINE": "baseline.json",
            "OUTPUT": "dist/merged.sgmodule", "MANIFEST": "dist/manifest.json",
            "REPORT": "security-report.txt", "MARKDOWN_REPORT": "security-report.md",
        }.items()}
        self.paths = paths
        patcher = patch.multiple(merge, **paths)
        patcher.start()
        self.addCleanup(patcher.stop)
        (self.root / "dist").mkdir()
        Path(merge.SOURCES_FILE).write_text(SOURCE + "\n" + SECOND_SOURCE + "\n", encoding="utf-8")
        Path(merge.OUTPUT).write_bytes(b"previous good module")
        Path(merge.MANIFEST).write_bytes(b"previous manifest")
        self.baseline = {
            "source_hashes": {SOURCE: merge.sha256(module_text()), SECOND_SOURCE: merge.sha256(module_text())},
            "scripts": {SCRIPT: merge.sha256(BODY)},
            "mitm_hosts": HOSTS,
            "section_counts": {"Rule": 10, "Script": 5},
            "script_count": 1,
        }
        Path(merge.BASELINE).write_text(json.dumps(self.baseline), encoding="utf-8")
        self.responses = {SOURCE: module_text(), SECOND_SOURCE: module_text(), SCRIPT: BODY}

    def run_merge(self):
        def fetch(url):
            response = self.responses[url]
            if isinstance(response, Exception):
                raise response
            return response

        with patch.object(merge, "fetch", side_effect=fetch) as mocked:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = merge.run()
        return code, mocked

    def assert_blocked(self, expected=2):
        before = {name: Path(self.paths[name]).read_bytes() for name in ("BASELINE", "OUTPUT", "MANIFEST")}
        code, mocked = self.run_merge()
        self.assertEqual(expected, code)
        for name, content in before.items():
            self.assertEqual(content, Path(self.paths[name]).read_bytes(), name)
        self.assertIn("FAIL", Path(merge.MARKDOWN_REPORT).read_text(encoding="utf-8"))
        return mocked

    def test_success_deduplicates_and_keeps_script_pins(self):
        self.responses[SOURCE] = module_text(rules=RULES + ["DOMAIN,new.example.com,REJECT"])
        code, _ = self.run_merge()
        self.assertEqual(0, code)
        output = Path(merge.OUTPUT).read_text(encoding="utf-8")
        self.assertEqual(1, output.count(RULES[0]))
        self.assertIn("new.example.com", output)
        baseline = json.loads(Path(merge.BASELINE).read_text(encoding="utf-8"))
        self.assertEqual(self.baseline["scripts"], baseline["scripts"])
        self.assertEqual(11, baseline["section_counts"]["Rule"])
        self.assertIn("SHA256", Path(merge.REPORT).read_text(encoding="utf-8"))

    def test_changed_script_is_blocked_and_old_outputs_are_preserved(self):
        self.responses[SCRIPT] = BODY + "// benign-looking change"
        self.assert_blocked()

    def test_unused_approved_pins_are_retained_without_distorting_active_count(self):
        self.baseline["scripts"][SCRIPT.replace("adblock.js", "inactive.js")] = merge.sha256("old script")
        Path(merge.BASELINE).write_text(json.dumps(self.baseline), encoding="utf-8")
        code, _ = self.run_merge()
        self.assertEqual(0, code)
        baseline = json.loads(Path(merge.BASELINE).read_text(encoding="utf-8"))
        self.assertEqual(self.baseline["scripts"], baseline["scripts"])
        self.assertEqual(1, baseline["script_count"])

    def test_script_download_failure_is_blocked(self):
        self.responses[SCRIPT] = OSError("offline")
        self.assert_blocked()

    def test_partial_source_failure_is_blocked(self):
        self.responses[SECOND_SOURCE] = OSError("offline")
        self.assert_blocked()

    def test_all_sources_failed_still_generates_report(self):
        self.responses[SOURCE] = self.responses[SECOND_SOURCE] = OSError("offline")
        self.assert_blocked()

    def test_unknown_script_same_allowed_host_is_not_downloaded(self):
        unknown = SCRIPT.replace("adblock.js", "unreviewed.js")
        self.responses[SOURCE] = module_text(scripts=[SCRIPT_LINES[0].replace(SCRIPT, unknown)])
        mocked = self.assert_blocked()
        self.assertNotIn(unknown, [call.args[0] for call in mocked.call_args_list])

    def test_sensitive_domain_is_blocked_case_insensitively(self):
        self.responses[SOURCE] = module_text(hosts=HOSTS + ["LOGIN.APPLE.COM."])
        self.assert_blocked()

    def test_wildcard_bypasses_are_blocked(self):
        for host in ("*", "*.com", "*.co.uk", "*.*", "api?.example.com", "*.apple.com", "*.example.com"):
            with self.subTest(host=host):
                self.assertTrue(merge.security_audit([host], [])[0])
        self.assertFalse(merge.security_audit(["m*.amap.com"], [])[0])

    def test_rule_growth_and_shrink_are_blocked_even_when_other_source_succeeds(self):
        for rules in (RULES + [f"DOMAIN,new{i}.com,REJECT" for i in range(3)], RULES[:7]):
            with self.subTest(count=len(rules)):
                self.responses[SOURCE] = self.responses[SECOND_SOURCE] = module_text(rules=rules)
                self.assert_blocked()

    def test_threshold_boundary_and_zero_baseline(self):
        self.assertFalse(merge.anomaly_audit(self.baseline, HOSTS, {"Rule": 12, "Script": 5}, 1)[0])
        self.assertFalse(merge.anomaly_audit(self.baseline, HOSTS, {"Rule": 8, "Script": 5}, 1)[0])
        self.assertTrue(merge.anomaly_audit(self.baseline, HOSTS, {"Rule": 10, "Script": 5, "Host": 1}, 1)[0])

    def test_mitm_growth_and_shrink_thresholds(self):
        self.assertTrue(merge.anomaly_audit(self.baseline, HOSTS[:3], {"Rule": 10, "Script": 5}, 1)[0])
        self.assertTrue(merge.anomaly_audit(self.baseline, HOSTS + ["a.com", "b.com"], {"Rule": 10, "Script": 5}, 1)[0])

    def test_small_rule_sections_allow_two_changes_but_block_three(self):
        for section in ("Rule", "URL Rewrite", "Map Local", "Body Rewrite", "Header Rewrite"):
            for old, new, blocked in ((1, 2, False), (1, 3, False), (1, 4, True),
                                      (5, 3, False), (5, 2, True)):
                with self.subTest(section=section, old=old, new=new):
                    baseline = {**self.baseline, "section_counts": {section: old}}
                    risks, notes = merge.anomaly_audit(baseline, HOSTS, {section: new}, 1)
                    self.assertEqual(blocked, bool(risks))
                    self.assertIn(f"[数量] {section}: {old} -> {new}（允许增减 2 条）", notes)

    def test_large_rule_sections_keep_twenty_percent_boundary(self):
        baseline = {**self.baseline, "section_counts": {"Rule": 100}}
        for new, blocked in ((120, False), (80, False), (121, True), (79, True)):
            with self.subTest(new=new):
                risks, _ = merge.anomaly_audit(baseline, HOSTS, {"Rule": new}, 1)
                self.assertEqual(blocked, bool(risks))

    def test_script_host_and_script_url_counts_do_not_get_two_entry_allowance(self):
        for section in ("Script", "Host"):
            with self.subTest(section=section):
                baseline = {**self.baseline, "section_counts": {section: 1}}
                self.assertTrue(merge.anomaly_audit(baseline, HOSTS, {section: 2}, 1)[0])
        self.assertTrue(merge.anomaly_audit(self.baseline, HOSTS, {"Rule": 10, "Script": 5}, 2)[0])

    def test_new_or_disappearing_small_sections_still_require_review(self):
        for section in ("Rule", "URL Rewrite", "Map Local", "Body Rewrite", "Header Rewrite"):
            for old, new in ((0, 1), (1, 0), (2, 0)):
                with self.subTest(section=section, old=old, new=new):
                    baseline = {**self.baseline, "section_counts": {section: old}}
                    self.assertTrue(merge.anomaly_audit(baseline, HOSTS, {section: new}, 1)[0])

    def test_small_header_growth_merges_successfully(self):
        self.baseline["section_counts"]["Header Rewrite"] = 1
        Path(merge.BASELINE).write_text(json.dumps(self.baseline), encoding="utf-8")
        headers = [f"^https://api.example.com/ header-del x-ad-{i}" for i in range(3)]
        self.responses[SOURCE] = module_text() + "\n[Header Rewrite]\n" + "\n".join(headers)
        code, _ = self.run_merge()
        self.assertEqual(0, code)
        baseline = json.loads(Path(merge.BASELINE).read_text(encoding="utf-8"))
        self.assertEqual(3, baseline["section_counts"]["Header Rewrite"])
        self.assertEqual(self.baseline["scripts"], baseline["scripts"])

    def test_excessive_small_header_growth_preserves_old_outputs(self):
        self.baseline["section_counts"]["Header Rewrite"] = 1
        Path(merge.BASELINE).write_text(json.dumps(self.baseline), encoding="utf-8")
        headers = [f"^https://api.example.com/ header-del x-ad-{i}" for i in range(4)]
        self.responses[SOURCE] = module_text() + "\n[Header Rewrite]\n" + "\n".join(headers)
        self.assert_blocked()

    def test_empty_source_is_blocked(self):
        self.responses[SOURCE] = "# empty module\n"
        self.assert_blocked()

    def test_empty_or_duplicate_source_list_is_blocked_before_download(self):
        for content in ("", SOURCE + "\n" + SOURCE):
            with self.subTest(content=content):
                Path(merge.SOURCES_FILE).write_text(content, encoding="utf-8")
                self.assert_blocked().assert_not_called()

    def test_missing_corrupt_or_invalid_baseline_is_blocked_before_download(self):
        Path(merge.BASELINE).unlink()
        code, mocked = self.run_merge()
        self.assertEqual(2, code)
        mocked.assert_not_called()
        for content in ("{broken", "{}", json.dumps({**self.baseline, "scripts": {SCRIPT: "bad hash"}})):
            with self.subTest(content=content):
                Path(merge.BASELINE).write_text(content, encoding="utf-8")
                self.assert_blocked().assert_not_called()

    def test_unknown_sections_or_unparsed_scripts_fail_closed(self):
        for content in ("[General]\nproxy = evil", "[Script]\nad = type=http-response",
                        "[Script]\nad = script-path=" + SCRIPT + ", script-path=" + SCRIPT,
                        "[Rule]\nad = script-path=" + SCRIPT,
                        "[MITM]\nca-passphrase = untrusted", "unsectioned input"):
            with self.subTest(content=content):
                self.responses[SOURCE] = content
                self.assert_blocked()

    def test_section_and_script_key_case_cannot_bypass_audit(self):
        sections = merge.parse_sections("[sCrIpT]\nad = type=http-response, SCRIPT-PATH=" + SCRIPT)
        self.assertEqual([SCRIPT], merge.extract_script_paths(sections["Script"]))

    def test_content_scanner_still_blocks_preapproved_dangerous_body(self):
        danger = "fetch('https://api.telegram.org/');"
        self.responses[SCRIPT] = danger
        self.baseline["scripts"][SCRIPT] = merge.sha256(danger)
        Path(merge.BASELINE).write_text(json.dumps(self.baseline), encoding="utf-8")
        self.assert_blocked()

    def test_unsafe_urls_are_rejected(self):
        for url in ("http://raw.githubusercontent.com/a.js", "file:///etc/passwd",
                    "https://raw.githubusercontent.com.evil.test/a.js",
                    "https://user@raw.githubusercontent.com/a.js", SCRIPT + "?raw=1",
                    SCRIPT + "#fragment", "https://raw.githubusercontent.com:444/a.js"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                merge.validate_url(url, merge.ALLOWED_SCRIPT_HOSTS)

    def test_redirect_is_rejected_before_following(self):
        with self.assertRaises(merge.SecurityError):
            merge.NoRedirect().redirect_request(None, None, 302, "Found", {}, "http://evil.test/script.js")

    def test_empty_large_and_invalid_utf8_downloads_fail(self):
        for data in (b"", b" " * 11, b"\xff"):
            with self.subTest(data=data):
                response = contextlib.nullcontext(io.BytesIO(data))
                with patch.object(merge.urllib.request, "build_opener") as opener:
                    opener.return_value.open.return_value = response
                    with patch.object(merge, "MAX_DOWNLOAD_BYTES", 10), self.assertRaises((ValueError, RuntimeError)):
                        merge.fetch(SCRIPT, retries=1)

    def test_report_escapes_upstream_html(self):
        merge.write_report(["<img src=x> @someone"], [], 0, 1)
        report = Path(merge.MARKDOWN_REPORT).read_text(encoding="utf-8")
        self.assertIn("&lt;img", report)
        self.assertNotIn("<img", report)


if __name__ == "__main__":
    unittest.main()
