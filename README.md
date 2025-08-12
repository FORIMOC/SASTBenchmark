# SASTBenchmark

1. BenchGen

从 NVD 中获取 CVE 数据，定位对应的带有漏洞的 Commit 和 Code 位置，然后将整理好的CVE以及代码片段整合到Benchmark中

- CVECollector: 从 NVD 中根据标准筛选 CVE 数据
- CCLocator(LLM Based CVE Vul Commit & Code Locator): 将筛选出来的 CVE 数据半自动化的每个定位漏洞代码位置
- BenchGen: CVE 数据和对应的漏洞代码片段整合到 Benchmark 中

2. SAST Crafter: Automatic Run SAST

自动搭建并运行 SAST，获取相关的 report

3. Report Verifier: LLM Based Report Verification

输入 CVE 和 SAST Report，输出 CVE 是否被 SAST 捕获

## CVEfix Limitations

CVEfix只搜集了所有commit，并diff分析了行号，以及以文件和函数粒度记录了每个commit的修改内容

但是，CVEfix没有做指出一个CVE的漏洞代码位置的工作，这对于我们的工作没有很大帮助

我们的目的是要准确获取到一个CVE对应的带有漏洞的commit版本以及对应的vul code位置，以此作为判断SAST是否捕获到了这个漏洞，cover了这个CVE

### 获取CVE对应的漏洞代码位置的难点

一个CVE的patch可能存在下面两种情况

- 多提交修复：一个CVE可能在多个提交之后才完全修复 -> 无法确定哪一个提交修复了核心漏洞代码
- 无关修改：在一个commit中可能包含多处文件修改，一些是和改CVE的修复相关，其他很大一部分则无关 -> diff之后也无法确定哪一部分是漏洞代码

这两种情况可能组合发生，我们认为需要加一个大模型验证的环节，如果存在上述情况，则组合人工核验

### 当前方法(CCLocator, Commit & Code Locator)

在CCLocator中我们要确定一个CVE的带有漏洞的Commit以及其漏洞代码的位置

1. 获取一个cve的所有相关commit（已完成）
2. 根据时间排序并找到最早的一个commit（已完成）
3. diff并将相关信息交给LLM判断是否包含核心漏洞代码

## 当前数据来源
- 2015-2024年NVD数据库
- 属于OWASP TOP 10 2021包含的CWE
- 属于Java、Python、Go、JavaScript、PHP五种语言之一

## CVEfix DB

CREATE TABLE IF NOT EXISTS "fixes" (
"cve_id" TEXT,
  "hash" TEXT,
  "repo_url" TEXT
);

CREATE TABLE IF NOT EXISTS "commits" (
"hash" TEXT,
  "repo_url" TEXT,
  "author" TEXT,
  "author_date" TEXT,
  "author_timezone" TEXT,
  "committer" TEXT,
  "committer_date" TEXT,
  "committer_timezone" TEXT,
  "msg" TEXT,
  "merge" TEXT,
  "parents" TEXT,
  "num_lines_added" TEXT,
  "num_lines_deleted" TEXT,
  "dmm_unit_complexity" TEXT,
  "dmm_unit_interfacing" TEXT,
  "dmm_unit_size" TEXT
);

CREATE TABLE IF NOT EXISTS "file_change" (
"file_change_id" TEXT,
  "hash" TEXT,
  "filename" TEXT,
  "old_path" TEXT,
  "new_path" TEXT,
  "change_type" TEXT,
  "diff" TEXT,
  "diff_parsed" TEXT,
  "num_lines_added" TEXT,
  "num_lines_deleted" TEXT,
  "code_after" TEXT,
  "code_before" TEXT,
  "nloc" TEXT,
  "complexity" TEXT,
  "token_count" TEXT,
  "programming_language" TEXT
);

CREATE TABLE IF NOT EXISTS "method_change" (
"method_change_id" TEXT,
  "file_change_id" TEXT,
  "name" TEXT,
  "signature" TEXT,
  "parameters" TEXT,
  "start_line" TEXT,
  "end_line" TEXT,
  "code" TEXT,
  "nloc" TEXT,
  "complexity" TEXT,
  "token_count" TEXT,
  "top_nesting_level" TEXT,
  "before_change" TEXT
);

CREATE TABLE IF NOT EXISTS "cve" (
"cve_id" TEXT,
  "published_date" TEXT,
  "last_modified_date" TEXT,
  "description" TEXT,
  "nodes" TEXT,
  "severity" TEXT,
  "obtain_all_privilege" TEXT,
  "obtain_user_privilege" TEXT,
  "obtain_other_privilege" TEXT,
  "user_interaction_required" TEXT,
  "cvss2_vector_string" TEXT,
  "cvss2_access_vector" TEXT,
  "cvss2_access_complexity" TEXT,
  "cvss2_authentication" TEXT,
  "cvss2_confidentiality_impact" TEXT,
  "cvss2_integrity_impact" TEXT,
  "cvss2_availability_impact" TEXT,
  "cvss2_base_score" TEXT,
  "cvss3_vector_string" TEXT,
  "cvss3_attack_vector" TEXT,
  "cvss3_attack_complexity" TEXT,
  "cvss3_privileges_required" TEXT,
  "cvss3_user_interaction" TEXT,
  "cvss3_scope" TEXT,
  "cvss3_confidentiality_impact" TEXT,
  "cvss3_integrity_impact" TEXT,
  "cvss3_availability_impact" TEXT,
  "cvss3_base_score" TEXT,
  "cvss3_base_severity" TEXT,
  "exploitability_score" TEXT,
  "impact_score" TEXT,
  "ac_insuf_info" TEXT,
  "reference_json" TEXT,
  "problemtype_json" TEXT
);

CREATE TABLE IF NOT EXISTS "cwe" (
"index" INTEGER,
  "cwe_id" TEXT,
  "cwe_name" TEXT,
  "description" TEXT,
  "extended_description" TEXT,
  "url" TEXT,
  "is_category" INTEGER
);

CREATE TABLE IF NOT EXISTS "cwe_classification" (
"cve_id" TEXT,
  "cwe_id" TEXT
);

CREATE TABLE IF NOT EXISTS "repository" (
"repo_url" TEXT,
  "repo_name" TEXT,
  "description" TEXT,
  "date_created" TEXT,
  "date_last_push" TEXT,
  "homepage" TEXT,
  "repo_language" TEXT,
  "owner" TEXT,
  "forks_count" TEXT,
  "stars_count" TEXT
);