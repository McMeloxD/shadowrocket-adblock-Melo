#!/usr/bin/env python3
"""聚合多个 Surge/Shadowrocket .sgmodule 去广告模块为单个模块，带安全校验。

流程：
1. 拉取 sources.txt 中所有上游模块。
2. 解析段落（[Rule]/[URL Rewrite]/[Map Local]/[Body Rewrite]/[Script]/[Host]/[MITM] 等）。
3. 抽取所有 script-path（远程脚本）并拉取其内容。
4. 安全校验（见 security_audit）：MITM 危险通配/敏感域、脚本源域名白名单、脚本外发特征、与基线对比。
5. 若发现高危风险 -> 写 security-report.txt 并 exit 2（不生成/不覆盖产物，保留上一版良品）。
6. 否则 -> 写 dist/merged.sgmodule + dist/manifest.json，刷新统计基线（不更新脚本 pin），exit 0。

退出码：0 安全通过；1 运行错误；2 安全或完整性检查失败（停更）。
"""
import hashlib
import html
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from collections import OrderedDict

ROOT = os.path.dirname(os.path.abspath(__file__))
SOURCES_FILE = os.path.join(ROOT, "sources.txt")
OUTPUT = os.path.join(ROOT, "dist", "merged.sgmodule")
MANIFEST = os.path.join(ROOT, "dist", "manifest.json")
BASELINE = os.path.join(ROOT, "baseline.json")
REPORT = os.path.join(ROOT, "security-report.txt")
MARKDOWN_REPORT = os.path.join(ROOT, "security-report.md")

PREFERRED_ORDER = ["Rule", "URL Rewrite", "Map Local", "Body Rewrite", "Host", "Script", "Header Rewrite"]
HEADER_NAME = "聚合去广告"

# ── 安全策略 ───────────────────────────────────────────────────────────────

# 允许托管远程脚本(script-path)的域名。新域名出现即视为供应链风险并停更。
ALLOWED_SCRIPT_HOSTS = {
    "raw.githubusercontent.com",  # fmz200 / kokoryh 等 GitHub 源
}
ALLOWED_SOURCE_HOSTS = {"raw.githubusercontent.com"}
# 新通配符必须修改此显式白名单；不能通过每天滚动基线自动获得信任。
ALLOWED_MITM_WILDCARDS = {"m*.amap.com"}
MAX_CHANGE_PERCENT = 20
# 已有普通规则段允许至少 2 条增删，避免小段落因百分比过大而频繁停更。
MIN_SECTION_CHANGE = 2
RELAXED_COUNT_SECTIONS = {"Rule", "URL Rewrite", "Map Local", "Body Rewrite", "Header Rewrite"}
MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024

# MITM 命中这些关键词(银行/支付/账号体系)即停更——绝不该解密这些域名。
MITM_SENSITIVE = [
    "alipay", "alipayobjects", "mypay", "tenpay", "wechatpay", "unionpay", "95516",
    "icbc", "ccb.com", "abchina", "boc.cn", "bankcomm", "cmbchina", "psbc", "cebbank",
    "spdb", "citicbank", "pingan", "10086.cn",  # 运营商账单等
    "icloud", "apple.com", "accounts.google", "paypal", "stripe",
]

# 脚本内容外发/投毒高危特征（命中即停更）。
SCRIPT_DANGER = [
    r"api\.telegram\.org",                       # TG bot 外发
    r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b",          # TG bot token
    r"discord(?:app)?\.com/api/webhooks",        # discord webhook
    r"hooks\.slack\.com",                         # slack webhook
    r"eval\s*\(\s*atob\s*\(",                     # 混淆执行
    r"Function\s*\(\s*atob\s*\(",
    r"new\s+Function\s*\(\s*['\"]return",         # 动态构造
    r"pastebin\.com/raw",
    r"webhook\.site",
    r"\beval\s*\(\s*unescape\s*\(",
]


class SecurityError(ValueError):
    pass


def validate_url(url, allowed_hosts):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in allowed_hosts
            or parsed.username or parsed.password or parsed.port not in (None, 443)
            or parsed.query or parsed.fragment or not parsed.path.startswith("/")
            or re.search(r"[\s\\\x00-\x1f\x7f]", url)):
        raise SecurityError(f"不允许的下载 URL: {url!r}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SecurityError("下载发生重定向，拒绝绕过来源白名单")


def fetch(url, retries=3, binary=False):
    validate_url(url, ALLOWED_SOURCE_HOSTS | ALLOWED_SCRIPT_HOSTS)
    opener = urllib.request.build_opener(NoRedirect())
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with opener.open(req, timeout=30) as r:
                data = r.read(MAX_DOWNLOAD_BYTES + 1)
                if len(data) > MAX_DOWNLOAD_BYTES or not data.strip():
                    raise SecurityError("下载为空或超过 10 MiB")
                return data if binary else data.decode("utf-8")
        except SecurityError:
            raise
        except Exception as e:  # noqa: BLE001
            last = e
            if i + 1 < retries:
                time.sleep(2 * (i + 1))
    raise RuntimeError(f"fetch failed after {retries}: {last}")


def sha256(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def parse_sections(text):
    sections = OrderedDict()
    cur = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^\[(.+?)\]\s*$", line)
        if m:
            names = {s.lower(): s for s in PREFERRED_ORDER + ["MITM"]}
            cur = names.get(m.group(1).strip().lower())
            if cur is None:
                raise SecurityError(f"未审核的模块段落: {m.group(1)!r}")
            sections.setdefault(cur, [])
            continue
        if cur is None or line.startswith("["):
            raise SecurityError("段落外内容或无效段落声明")
        if cur != "Script" and re.search(r"\bscript-path\s*=", line, re.I):
            raise SecurityError("Script 段之外的脚本引用")
        sections[cur].append(line)
    return sections


def extract_script_paths(script_lines):
    paths = []
    for ln in script_lines:
        matches = re.findall(r"(?:^|,)\s*script-path\s*=\s*([^,\s]+)", ln, re.I)
        if len(matches) != 1 or len(re.findall(r"\bscript-path\s*=", ln, re.I)) != 1:
            raise SecurityError("脚本行必须含唯一、可解析的 script-path")
        paths.append(matches[0])
    return paths


def host_of(url):
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:  # noqa: BLE001
        return ""


def mitm_hosts_from(lines):
    out = []
    for ln in lines:
        match = re.fullmatch(r"hostname\s*=\s*(?:%APPEND%\s*)?(.+)", ln, re.I)
        if not match:
            raise SecurityError("MITM 段只允许 hostname，不接受证书或其他配置")
        rhs = match.group(1)
        for h in rhs.split(","):
            h = h.strip()
            if not h:
                raise SecurityError("MITM hostname 包含空项")
            out.append(h.lower().rstrip("."))
    return out


def is_dangerous_wildcard(host):
    """只放行人工审核的精确通配表达式，包含公共后缀的宽泛通配默认拒绝。"""
    return ("*" in host or "?" in host) and host not in ALLOWED_MITM_WILDCARDS


def security_audit(mitm_hosts, scripts):
    """返回 (risks:list[str], notes:list[str])。risks 非空即停更。"""
    risks, notes = [], []

    # 1. MITM 危险通配
    for h in mitm_hosts:
        candidate = h.replace("*", "a")
        if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", candidate):
            risks.append(f"[MITM] 非法域名: {h!r}")
        if is_dangerous_wildcard(h):
            risks.append(f"[MITM] 危险通配域名: {h!r}（会解密过大范围流量）")

    # 2. MITM 敏感域
    for h in mitm_hosts:
        low = h.lower()
        for kw in MITM_SENSITIVE:
            if kw in low:
                risks.append(f"[MITM] 命中敏感域(银行/支付/账号): {h!r} ~ '{kw}'")
                break

    # 3 & 4. 脚本源白名单 + 内容外发特征
    for sp in scripts:
        url = sp["url"]
        host = sp["host"]
        if host not in ALLOWED_SCRIPT_HOSTS:
            risks.append(f"[Script] 脚本来自白名单外域名(疑似供应链投毒): {host} <- {url}")
        body = sp.get("body", "")
        if sp.get("fetch_error"):
            risks.append(f"[Script] 拉取失败，无法扫描: {url} ({sp['fetch_error']})")
            continue
        for pat in SCRIPT_DANGER:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                risks.append(f"[Script] 命中外发/投毒特征 /{pat}/  ({url})")
    return risks, notes


def load_baseline():
    try:
        with open(BASELINE, encoding="utf-8") as f:
            baseline = json.load(f)
        for key in ("source_hashes", "scripts"):
            entries = baseline[key]
            if not isinstance(entries, dict) or not entries:
                raise ValueError(f"{key} 必须是非空映射")
            for url, digest in entries.items():
                validate_url(url, ALLOWED_SCRIPT_HOSTS if key == "scripts" else ALLOWED_SOURCE_HOSTS)
                if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                    raise ValueError(f"{key} 的 SHA256 无效")
        hosts = baseline["mitm_hosts"]
        counts = baseline["section_counts"]
        if not isinstance(hosts, list) or any(not isinstance(h, str) for h in hosts):
            raise ValueError("mitm_hosts 无效")
        if (not isinstance(counts, dict) or not counts
                or any(k not in PREFERRED_ORDER or type(v) is not int or v < 0 for k, v in counts.items())):
            raise ValueError("section_counts 无效")
        if type(baseline["script_count"]) is not int or baseline["script_count"] < 0:
            raise ValueError("script_count 无效")
        return baseline
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise SecurityError(f"可信基线缺失或损坏，必须人工修复: {e}") from e


def anomaly_audit(baseline, mitm_hosts, section_counts, script_count):
    risks, notes = [], []
    metrics = [("MITM", len(baseline["mitm_hosts"]), len(mitm_hosts)),
               ("脚本 URL", baseline["script_count"], script_count)]
    metrics += [(name, baseline["section_counts"].get(name, 0), section_counts.get(name, 0))
                for name in sorted(set(baseline["section_counts"]) | set(section_counts))]
    for name, old, new in metrics:
        limit = old * MAX_CHANGE_PERCENT // 100
        if old > 0 and name in RELAXED_COUNT_SECTIONS:
            limit = max(limit, MIN_SECTION_CHANGE)
        notes.append(f"[数量] {name}: {old} -> {new}（允许增减 {limit} 条）")
        if old > 0 and new == 0:
            risks.append(f"[异常] {name}: {old} -> 0，已有内容全部消失，需人工审核")
        elif abs(new - old) > limit:
            risks.append(f"[异常] {name}: {old} -> {new}，增减超过允许的 {limit} 条（零基线禁止自动新增）")
    old_hosts, new_hosts = set(baseline["mitm_hosts"]), set(mitm_hosts)
    notes += [f"[MITM 新增] {h}" for h in sorted(new_hosts - old_hosts)]
    notes += [f"[MITM 删除] {h}" for h in sorted(old_hosts - new_hosts)]
    return risks, notes


def diff_notes(baseline, source_hashes, script_index):
    notes = []
    old_src = baseline.get("source_hashes", {})
    for url, h in source_hashes.items():
        if url in old_src and old_src[url] != h:
            notes.append(f"[变更] 上游模块: {url} SHA256 {old_src[url]} -> {h}")
        elif url not in old_src:
            notes.append(f"[新增] 新上游模块: {url} SHA256 {h}")
    notes += [f"[删除] 上游模块: {url}" for url in sorted(set(old_src) - set(source_hashes))]
    old_scripts = baseline.get("scripts", {})
    for url, h in script_index.items():
        if url in old_scripts and old_scripts[url] != h:
            notes.append(f"[变更] 远程脚本: {url} SHA256 {old_scripts[url]} -> {h}")
        elif url not in old_scripts:
            notes.append(f"[新增] 新远程脚本: {url} SHA256 {h}")
    notes += [f"[未拉取/删除] 远程脚本: {url}" for url in sorted(set(old_scripts) - set(script_index))]
    return notes


def write_report(risks, notes, ok, total):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    lines = [
        "shadowrocket-adblock 安全校验报告",
        f"时间(UTC): {ts}",
        f"拉取源: {ok}/{total}",
        "",
        f"风险(停更触发): {len(risks)}",
    ]
    lines += [f"  - {r}" for r in risks] or ["  （无）"]
    lines += ["", f"提示/变更: {len(notes)}"]
    lines += [f"  - {n}" for n in notes] or ["  （无）"]
    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    # 转义不可信上游内容，避免报告变成 HTML、链接或提及。
    with open(MARKDOWN_REPORT, "w", encoding="utf-8") as f:
        f.write("# 合并安全报告\n\n" + ("**FAIL：禁止发布**" if risks else "**PASS**") + "\n\n<pre>\n")
        f.write(html.escape("\n".join(lines)))
        f.write("\n</pre>\n")


def main():
    baseline = load_baseline()
    with open(SOURCES_FILE, encoding="utf-8") as f:
        urls = [l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")]
    if not urls or len(urls) != len(set(urls)):
        raise SecurityError("sources.txt 不能为空或包含重复来源")
    for url in urls:
        validate_url(url, ALLOWED_SOURCE_HOSTS)

    buckets, seen = OrderedDict(), {}
    mitm_hosts = []
    source_hashes = {}
    script_urls = []
    ok, failed = 0, []
    risks = []

    for url in urls:
        try:
            txt = fetch(url)
        except Exception as e:  # noqa: BLE001
            print(f"WARN: 源拉取失败 {url}\n      {e}", file=sys.stderr)
            failed.append(url)
            continue
        ok += 1
        source_hashes[url] = sha256(txt)
        sections = parse_sections(txt)
        if not any(sections.values()):
            risks.append(f"[Source] 模块没有有效内容: {url}")
        for name, lines in sections.items():
            if name.lower() == "mitm":
                mitm_hosts += mitm_hosts_from(lines)
                continue
            if name.lower() == "script":
                script_urls += extract_script_paths(lines)
            buckets.setdefault(name, [])
            seen.setdefault(name, set())
            for ln in lines:
                if ln not in seen[name]:
                    seen[name].add(ln)
                    buckets[name].append(ln)

    risks += [f"[Source] 模块拉取失败，拒绝发布残缺产物: {url}" for url in failed]

    # 去重 MITM / 脚本
    mitm_hosts = list(dict.fromkeys(mitm_hosts))
    script_urls = list(dict.fromkeys(script_urls))

    # 拉取并扫描每个远程脚本
    scripts = []
    script_index = {}
    for su in script_urls:
        entry = {"url": su, "host": host_of(su)}
        try:
            validate_url(su, ALLOWED_SCRIPT_HOSTS)
            if su not in baseline["scripts"]:
                raise SecurityError("完整脚本 URL 未在 baseline.json 审核，不下载未知脚本")
            body = fetch(su)
            entry["body"] = body
            script_index[su] = sha256(body)
        except Exception as e:  # noqa: BLE001
            entry["fetch_error"] = str(e)
        scripts.append(entry)

    # 安全校验
    audit_risks, audit_notes = security_audit(mitm_hosts, scripts)
    risks += audit_risks
    for url, digest in script_index.items():
        if digest != baseline["scripts"][url]:
            risks.append(f"[Script] SHA256 与人工审核 pin 不符: {url}")
    section_counts = {name: len(lines) for name, lines in buckets.items()}
    anomaly_risks, count_notes = anomaly_audit(baseline, mitm_hosts, section_counts, len(script_urls))
    risks += anomaly_risks
    notes = audit_notes + diff_notes(baseline, source_hashes, script_index) + count_notes

    write_report(risks, notes, ok, len(urls))

    if risks:
        print("SECURITY RISK: 检测到风险，停止更新，保留上一版产物。", file=sys.stderr)
        for r in risks:
            print("  RISK " + r, file=sys.stderr)
        return 2

    # ── 安全通过：写产物 ──
    ordered = [s for s in PREFERRED_ORDER if s in buckets]
    ordered += [s for s in buckets if s not in PREFERRED_ORDER]
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    out = [
        f"#!name={HEADER_NAME}",
        f"#!desc=每日自动合并+安全校验 | 源 {ok} | MITM {len(mitm_hosts)} | 脚本 {len(scripts)} | {ts} UTC",
        "#!category=广告拦截",
        "#!author=memoryttt (auto-merge, security-checked)",
        "",
    ]
    for name in ordered:
        if not buckets[name]:
            continue
        out.append(f"[{name}]")
        out.extend(buckets[name])
        out.append("")
    if mitm_hosts:
        out.append("[MITM]")
        out.append("hostname = %APPEND% " + ", ".join(mitm_hosts))
        out.append("")

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump({
            "generated": ts + " UTC",
            "sources_ok": ok, "sources_total": len(urls),
            "mitm_hosts": mitm_hosts,
            "scripts": [{"url": s["url"], "host": s["host"]} for s in scripts],
            "section_counts": section_counts,
            "script_count": len(script_urls),
        }, f, ensure_ascii=False, indent=2)

    # 刷新基线（仅在安全通过时更新，作为下次比对的可信参照）
    with open(BASELINE, "w", encoding="utf-8") as f:
        json.dump({
            "updated": ts + " UTC",
            "source_hashes": source_hashes,
            "scripts": baseline["scripts"],
            "mitm_hosts": mitm_hosts,
            "section_counts": section_counts,
            "script_count": len(script_urls),
        }, f, ensure_ascii=False, indent=2)

    print(f"OK: 安全通过，合并 {ok}/{len(urls)} 源 -> {OUTPUT}")
    print(f"    段落: {', '.join(ordered)} | MITM {len(mitm_hosts)} | 脚本 {len(scripts)}")
    if notes:
        print(f"    变更提示 {len(notes)} 条（见 security-report.txt）")
    if failed:
        print(f"    失败源 {len(failed)}: {failed}")


def run():
    try:
        return main() or 0
    except Exception as e:  # noqa: BLE001
        write_report([f"[{type(e).__name__}] {e}"], [], 0, 0)
        print(f"ERROR: {e}，停止更新，禁止发布", file=sys.stderr)
        return 2 if isinstance(e, SecurityError) else 1


if __name__ == "__main__":
    sys.exit(run())
