import json
import os
import subprocess
from urllib.parse import urlparse

workspace_path = "src/sast_crafter/workspace"
data_path = "src/sast_crafter/data_example/result.json"

def get_repo_name(repo_url):
    """
    提取 repo owner 和 repo 名称，用于创建唯一目录名
    """
    parsed = urlparse(repo_url)
    parts = parsed.path.strip("/").split("/")
    if len(parts) >= 2:
        owner, repo = parts[-2], parts[-1].replace(".git", "")
        return f"{owner}_{repo}"
    raise ValueError(f"Invalid repo URL: {repo_url}")

def clone_and_checkout(repo_url, commit, dest_path):
    """
    克隆仓库（如果未克隆），并切换到指定 commit
    """
    if not os.path.exists(dest_path):
        print(f"[+] Cloning {repo_url} to {dest_path}")
        subprocess.run(["git", "clone", repo_url, dest_path], check=True)
    else:
        print(f"[=] Repo already exists at {dest_path}, skipping clone")

    print(f"[>] Checking out commit {commit}")
    subprocess.run(["git", "fetch"], cwd=dest_path, check=True)
    subprocess.run(["git", "checkout", commit], cwd=dest_path, check=True)

def process_json_repos(json_path, workspace_path):
    """
    处理 JSON 中的每个记录，克隆并切换 commit，返回路径和语言
    Yields:
        (repo_path: str, language: str)
    """
    with open(json_path, "r") as f:
        records = json.load(f)

    os.makedirs(workspace_path, exist_ok=True)

    for record in records:
        repo_url = record.get("Repo")
        commit = record.get("VulnerableCommit")
        language = record.get("Language", "python").lower()  # 默认是 python

        if not repo_url or not commit:
            print(f"[!] Skipping incomplete record: {record}")
            continue

        folder_name = get_repo_name(repo_url)
        dest_path = os.path.join(workspace_path, folder_name)

        try:
            clone_and_checkout(repo_url, commit, dest_path)
            yield dest_path, language
        except subprocess.CalledProcessError as e:
            print(f"[X] Failed to process {repo_url}@{commit}: {e}")


def run_semgrep_scan(project_path, language, output_file=None):
    rule_pack = f"p/{language}"

    cmd = ["semgrep", "--config", rule_pack, project_path]
    if output_file:
        cmd += ["--json", "--output", output_file]

    try:
        print(f"[+] Running Semgrep on {project_path} with {rule_pack}")
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[X] Semgrep failed on {project_path}: {e}")

# 主程序
if __name__ == "__main__":
    for repo_path, lang in process_json_repos(data_path, workspace_path):
        output_file = os.path.join(repo_path, f"semgrep_{repo_path.split('/')[-1]}.json")
        run_semgrep_scan(repo_path, lang, output_file=output_file)
