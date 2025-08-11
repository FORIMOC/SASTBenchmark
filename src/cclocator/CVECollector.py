import time
import re
import requests
import json
from datetime import datetime, timedelta

from src.cclocator.github_api import *
from src.utils.vul_class import OWASP_TOP10_2021_CWE

TOP_CWE_SET = {cwe for group in OWASP_TOP10_2021_CWE for cwe in group}
HASH_PATTERN = re.compile(r"/([0-9a-fA-F]{40})(/|$)")
ALLOWED_LANGUAGES = {"Python", "Java", "JavaScript", "Go", "PHP"}

PATCH_KEYWORDS = ["fix", "remove", "patch", "repair", "resolve", "vuln"]


class CVECollector:
    def __init__(self):
        self.results = []

    def is_top_cwe(self, cwe_ids):
        return any(cwe in TOP_CWE_SET for cwe in cwe_ids)

    def contains_patch_keyword(self, message):
        return any(kw in message.lower() for kw in PATCH_KEYWORDS)

    def parse_github_info(self, url):
        match = re.match(r"https://github\.com/([^/]+)/([^/]+)/(commit|blob)/([0-9a-fA-F]{40})", url)
        if not match:
            return None
        owner, repo, kind, sha = match.groups()
        return owner, repo, kind, sha

    def split_date_ranges(self, start_date_str, end_date_str, max_days=120):
        """
        将日期区间拆分为多个小于等于max_days天的区间。
        """
        start = datetime.fromisoformat(start_date_str)
        end = datetime.fromisoformat(end_date_str)
        delta = timedelta(days=max_days)
        ranges = []

        while start < end:
            range_end = min(start + delta, end)
            ranges.append((start.isoformat() + "Z", range_end.isoformat() + "Z"))
            start = range_end + timedelta(seconds=1)

        return ranges

    def fetch_cve_data(self, start_date="2024-01-01T00:00:00.000Z", end_date="2024-01-03T23:59:59.999Z"):
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        start_index = 0
        total_results = 1

        while start_index < total_results:
            # 检查 github API 配额
            # check_github_rate_limit()

            params = {
                "pubStartDate": start_date,
                "pubEndDate": end_date,
                "startIndex": start_index,
                "resultsPerPage": 200
            }

            print(f"[+] 正在获取第 {start_index} 条之后的数据")
            response = requests.get(base_url, params=params, timeout=15)
            response.raise_for_status()
            data = response.json()

            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])

            # 遍历 200 个 CVE
            for item in vulnerabilities:
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                weaknesses = cve.get("weaknesses", [])
                refs = cve.get("references", [])

                # 获取并去重 CWE 编号
                cwe_ids = set()
                for w in weaknesses:
                    for desc in w.get("description", []):
                        if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                            cwe_ids.add(desc["value"].replace("CWE-", ""))
                cwe_ids = list(cwe_ids)

                # 不是 Top 15 CWE 列表中的漏洞，跳过
                if not self.is_top_cwe(cwe_ids):
                    continue

                # 取 CVSS 分数和向量
                cvss_info = {}
                metrics = cve.get("metrics", {})
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics:
                        cvss_info = metrics[key][0].get("cvssData", {})
                        break

                # 获取 ref 信息并解析，同时检查语言
                commit_infos = []
                language = None
                language_checked = False
                skip_repo = False

                for ref in refs:
                    url = ref.get("url", "")
                    if "github.com" in url and ("commit" in url or "blob" in url) and HASH_PATTERN.search(url):
                        info = self.parse_github_info(url)
                        if info:
                            owner, repo, kind, sha = info

                            if not language_checked:
                                language = get_repo_language(owner, repo)
                                language_checked = True
                                if language not in ALLOWED_LANGUAGES:
                                    print(f"[-] 跳过 {owner}/{repo}，语言 {language} 不符合要求")
                                    skip_repo = True
                                    break

                            commit_time = get_commit_time(owner, repo, sha)
                            if commit_time:
                                commit_infos.append({
                                    "url": url,
                                    "time": commit_time,
                                    "sha": sha,
                                    "repo": f"{owner}/{repo}",
                                    "kind": kind
                                })
                            time.sleep(1)

                if skip_repo or not commit_infos:
                    continue

                # 优先选择 blob 类型的记录
                blob_candidates = [info for info in commit_infos if info["kind"] == "blob"]
                if blob_candidates:
                    blob_candidates.sort(key=lambda x: datetime.fromisoformat(x["time"].replace("Z", "+00:00")))
                    best = blob_candidates[0]
                    vulnerable_commit = best["sha"]
                else:
                    # 没有 blob，则选择 commit 类型的记录，并获取其 parent commit
                    commit_candidates = [info for info in commit_infos if info["kind"] == "commit"]
                    if not commit_candidates:
                        continue
                    commit_candidates.sort(key=lambda x: datetime.fromisoformat(x["time"].replace("Z", "+00:00")))
                    best = commit_candidates[0]
                    owner, repo = best["repo"].split("/")
                    commit_message = get_commit_message(owner, repo, best["sha"])
                    if self.contains_patch_keyword(commit_message):
                        vulnerable_commit = get_parent_commit(owner, repo, best["sha"]) or best["sha"]
                    else:
                        vulnerable_commit = best["sha"]

                result = {
                    "CVEID": cve_id,
                    "CWEIDs": cwe_ids,
                    "Repo": f"https://github.com/{best['repo']}",
                    "Language": language,
                    "VulnerableCommit": vulnerable_commit,
                    "PatchInfo": {
                        "URL": best["url"],
                        "Time": best["time"],
                        "Kind": best["kind"],
                    },
                    "refs": refs,
                    "CVSS": cvss_info
                }

                print(f"\n===== {cve_id} =====")
                print(f"CWEIDs: {', '.join(cwe_ids)}")
                print(f"Repo: {result['Repo']}")
                print(f"Language: {language}")
                print(f"Vulnerable Commit: {vulnerable_commit}")
                print(f"Patch URL: {best['url']}")
                print(f"Patch Time: {best['time']}")

                self.results.append(result)

            start_index += params["resultsPerPage"]

        # 存储到文件
        with open("result.json", "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"\n[+] 已保存到 result.json，共 {len(self.results)} 条结果")

    def fetch_cve_data_batch(self, start="2024-01-01", end="2024-12-31", max_retries=999, retry_wait=5):
        date_ranges = self.split_date_ranges(start, end, max_days=120)

        for i, (start_iso, end_iso) in enumerate(date_ranges):
            print(f"\n=== 第{i + 1}段：{start_iso} - {end_iso} ===")
            retries = 0
            while retries < max_retries:
                try:
                    self.fetch_cve_data(start_date=start_iso, end_date=end_iso)
                    print(f"[+] 第{i + 1}段成功完成")
                    break  # 成功跳出重试循环
                except Exception as e:
                    retries += 1
                    print(f"[-] 第{i + 1}段出现错误: {e}，等待{retry_wait}秒后重试({retries}/{max_retries})")
                    time.sleep(retry_wait)
            else:
                print(f"[!] 第{i + 1}段重试达到最大次数，跳过该段继续执行下一段")
            time.sleep(5)  # 避免NVD API限速