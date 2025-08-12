import requests
import os
import time
from functools import wraps

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}


def check_github_rate_limit(threshold=50, max_retries=999, retry_wait=5):
    for attempt in range(1, max_retries + 1):
        try:
            url = "https://api.github.com/rate_limit"
            r = requests.get(url, headers=HEADERS, timeout=10)
            r.raise_for_status()
            data = r.json()
            remaining = data["rate"]["remaining"]
            reset_time = data["rate"]["reset"]  # Unix timestamp

            print(f"[~] GitHub API 剩余配额: {remaining}")
            if remaining < threshold:
                now = int(time.time())
                wait_seconds = reset_time - now
                if wait_seconds > 0:
                    reset_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(reset_time))
                    print(f"[!] 配额不足，等待 {wait_seconds // 60} 分钟直到 {reset_str}")
                    time.sleep(wait_seconds)
            return  # 成功检查配额后直接返回
        except Exception as e:
            print(f"[!] 第 {attempt}/{max_retries} 次检查 GitHub 配额失败: {e}")
            if attempt < max_retries:
                print(f"    等待 {retry_wait} 秒后重试...")
                time.sleep(retry_wait)
            else:
                print(f"[x] 连续 {max_retries} 次检查配额失败，默认等待 1 小时")
                time.sleep(3600)


def with_retries(max_retries=5, wait_seconds=5):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    print(f"[-] {func.__name__} 调用失败（第 {attempt + 1} 次）: {e}")
                    if attempt < max_retries - 1:
                        time.sleep(wait_seconds)
            print(f"[!] {func.__name__} 多次重试失败，返回 None")
            return None

        return wrapper

    return decorator


@with_retries(max_retries=999, wait_seconds=5)
def get_commit_diff(owner, repo, sha):
    """
    获取指定 commit 的结构化 diff 信息（JSON 格式）
    每个文件包含 filename、status、additions、deletions、changes、patch 等
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    headers = HEADERS.copy()
    headers["Accept"] = "application/vnd.github.v3+json"  # JSON 格式
    r = requests.get(url, headers=headers, timeout=15)
    r.raise_for_status()
    data = r.json()

    files_info = []
    for f in data.get("files", []):
        files_info.append({
            "filename": f["filename"],
            "status": f["status"],         # modified / added / removed / renamed
            "additions": f["additions"],   # 新增行数
            "deletions": f["deletions"],   # 删除行数
            "changes": f["changes"],       # 总改动数
            "patch": f.get("patch", "")    # diff 片段（带 @@ 行号信息）
        })

    return files_info


@with_retries(max_retries=999, wait_seconds=5)
def get_commit_message(owner, repo, sha):
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
        data = r.json()
        return data["commit"]["message"]
    except Exception as e:
        print(f"[-] 获取 commit message 失败: {url} - {e}")
        return ""


@with_retries(max_retries=999, wait_seconds=5)
def get_commit_time(owner, repo, sha):
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
        data = r.json()
        return data["commit"]["committer"]["date"]
    except Exception as e:
        print(f"[-] 获取提交时间失败: {url} - {e}")
        return None


@with_retries(max_retries=999, wait_seconds=5)
def get_parent_commit(owner, repo, sha):
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
        data = r.json()
        parents = data.get("parents", [])
        if parents:
            return parents[0]["sha"]
    except Exception as e:
        print(f"[-] 获取 parent commit 失败: {url} - {e}")
    return None


@with_retries(max_retries=999, wait_seconds=5)
def get_repo_language(owner, repo):
    repo_url = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        r = requests.get(repo_url, headers=HEADERS, timeout=15)
        r.raise_for_status()
        data = r.json()
        primary_lang = data.get("language")

        if primary_lang == "HTML":
            # 获取语言分布
            lang_url = f"https://api.github.com/repos/{owner}/{repo}/languages"
            r2 = requests.get(lang_url, headers=HEADERS, timeout=15)
            r2.raise_for_status()
            lang_data = r2.json()
            sorted_langs = sorted(lang_data.items(), key=lambda x: x[1], reverse=True)

            if len(sorted_langs) > 1:
                # 返回第二语言
                return sorted_langs[1][0]
            elif sorted_langs:
                # 只有一种语言
                return sorted_langs[0][0]
            else:
                return None

        return primary_lang

    except Exception as e:
        print(f"[-] 获取语言失败: {repo_url} - {e}")
        return None
