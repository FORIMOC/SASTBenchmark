import re

from src.bot.bot import LLMBot


class CCLocator:
    def __init__(self, cve_info):
        self.cve_info = cve_info
        # 预处理 diff 信息
        for diff in self.cve_info["PatchInfo"]["Diff"]:
            diff["patch"] = self.parse_diff(diff["patch"])
        print(self.cve_info)

    def parse_diff(self, patch_text):
        hunks = []
        current_hunk = None

        lines = patch_text.splitlines()
        hunk_header_re = re.compile(r"^@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@")

        for line in lines:
            header_match = hunk_header_re.match(line)
            if header_match:
                # 如果已有 hunk，先保存
                if current_hunk:
                    hunks.append(current_hunk)

                old_start = int(header_match.group(1))
                old_count = int(header_match.group(2) or 1)
                new_start = int(header_match.group(3))
                new_count = int(header_match.group(4) or 1)

                current_hunk = {
                    "old_start": old_start,
                    "old_count": old_count,
                    "new_start": new_start,
                    "new_count": new_count,
                    "changes": []
                }

                # 初始化行号计数器
                old_line = old_start
                new_line = new_start
                continue

            if current_hunk is not None:
                if line.startswith('-'):
                    current_hunk["changes"].append({
                        "type": "remove",
                        "content": line[1:],
                        "old_lineno": old_line
                    })
                    old_line += 1
                elif line.startswith('+'):
                    current_hunk["changes"].append({
                        "type": "add",
                        "content": line[1:]
                    })
                    new_line += 1
                else:
                    current_hunk["changes"].append({
                        "content": line[1:] if line.startswith(' ') else line
                    })
                    old_line += 1
                    new_line += 1

        if current_hunk:
            hunks.append(current_hunk)

        return hunks


    def locate_vul_code(self):
        """
        使用 LLM 定位漏洞代码。
        """
        cve_context = {
            "CVEID": self.cve_info["CVEID"],
            "CWEIDs": self.cve_info["CWEIDs"],
            "PatchInfo": self.cve_info["PatchInfo"],
        }
        prompt = f"""帮我判断一下下面的patch是否是修复这个CVE的，如果是请帮我指出该CVE的漏洞代码位置也就是sink点（文件路径+行号信息）

                输出要求：
                只输出文件路径和行号信息以及起始行的代码内容，不要输出其他内容
                如果diff信息中不包含sink点代码，则输出"没有找到漏洞代码"


                cve信息：
                {cve_context}
                """
        bot = LLMBot()
        resp = bot.query(prompt)
        print(resp)


cc_locator = CCLocator({
    "CVEID": "CVE-2024-53999",
    "CWEIDs": [
      "79"
    ],
    "Repo": "https://github.com/MobSF/Mobile-Security-Framework-MobSF",
    "Language": "JavaScript",
    "VulnerableCommit": "0d3b1ec3b9f61ee68d349c1cc10d53ee96eef3f2",
    "PatchInfo": {
      "URL": "https://github.com/MobSF/Mobile-Security-Framework-MobSF/commit/27d165872847f5ae7417caf09f37edeeba741e1e",
      "Time": "2024-12-03T06:33:01Z",
      "Message": "Fixes a stored XSS in Recent Scans diff APK, GHSA-5jc6-h9w7-jm3p",
      "Diff": [
        {
          "filename": "mobsf/MobSF/init.py",
          "status": "modified",
          "additions": 1,
          "deletions": 1,
          "changes": 2,
          "patch": "@@ -18,7 +18,7 @@\n \n logger = logging.getLogger(__name__)\n \n-VERSION = '4.2.8'\n+VERSION = '4.2.9'\n BANNER = r\"\"\"\n   __  __       _    ____  _____       _  _    ____  \n  |  \\/  | ___ | |__/ ___||  ___|_   _| || |  |___ \\ "
        },
        {
          "filename": "mobsf/MobSF/views/home.py",
          "status": "modified",
          "additions": 1,
          "deletions": 1,
          "changes": 2,
          "patch": "@@ -163,7 +163,7 @@ def upload(self):\n         request = self.request\n         scanning = Scanning(request)\n         content_type = self.file.content_type\n-        file_name = self.file.name\n+        file_name = sanitize_filename(self.file.name)\n         logger.info('MIME Type: %s FILE: %s', content_type, file_name)\n         if self.file_type.is_apk():\n             return scanning.scan_apk()"
        },
        {
          "filename": "mobsf/MobSF/views/scanning.py",
          "status": "modified",
          "additions": 3,
          "deletions": 1,
          "changes": 4,
          "patch": "@@ -8,6 +8,7 @@\n from django.utils import timezone\n \n from mobsf.StaticAnalyzer.models import RecentScansDB\n+from mobsf.MobSF.security import sanitize_filename\n \n logger = logging.getLogger(__name__)\n \n@@ -62,7 +63,8 @@ class Scanning(object):\n \n     def __init__(self, request):\n         self.file = request.FILES['file']\n-        self.file_name = request.FILES['file'].name\n+        self.file_name = sanitize_filename(\n+            request.FILES['file'].name)\n         self.data = {\n             'analyzer': 'static_analyzer',\n             'status': 'success',"
        },
        {
          "filename": "mobsf/templates/general/recent.html",
          "status": "modified",
          "additions": 15,
          "deletions": 3,
          "changes": 18,
          "patch": "@@ -184,6 +184,18 @@ <h3 class=\"box-title\"><i class=\"fa fa-rocket\"></i> Recent Scans</h3>\n {% block extra_scripts %}\n <script src=\"{% static \"adminlte/plugins/sweetalert2/sweetalert2.min.js\" %}\"></script>\n <script>\n+\n+    // Escape HTML\n+    function escapeHtml(unsafe)\n+    {\n+        return unsafe\n+            .replace(/&/g, \"&amp;\")\n+            .replace(/</g, \"&lt;\")\n+            .replace(/>/g, \"&gt;\")\n+            .replace(/\"/g, \"&quot;\")\n+            .replace(/'/g, \"&#039;\");\n+    }\n+\n     // Diff functions\n     var diff_first_md5 = '';\n     var diff_first_name = '';\n@@ -231,7 +243,7 @@ <h3 class=\"box-title\"><i class=\"fa fa-rocket\"></i> Recent Scans</h3>\n     }\n \n     function diff_cleanup() {\n-        first_td_id = diff_first_md5 + '_' + diff_first_name;\n+        first_td_id = diff_first_md5 + '_' + escapeHtml(diff_first_name);\n         $('[id=\"' + first_td_id + '\"]').closest(\"tr\").removeClass(\"selected\");\n         $('[id=\"' + first_td_id + '\"]').closest(\"tbody\").removeClass(\"selectable_table\");\n         diff_first_md5 = \"\";\n@@ -254,8 +266,8 @@ <h3 class=\"box-title\"><i class=\"fa fa-rocket\"></i> Recent Scans</h3>\n             title: '<strong>Diff confirmation</strong>',\n             type: 'info',\n             html:\n-                '<strong>Do you want to diff - </strong><br />' + diff_first_name +\n-                '<br /> <strong>with - <br /> </strong>' + diff_second_name + ' <br /> <strong>?</strong>',\n+                '<strong>Do you want to diff - </strong><br />' + escapeHtml(diff_first_name) +\n+                '<br /> <strong>with - <br /> </strong>' + escapeHtml(diff_second_name) + ' <br /> <strong>?</strong>',\n \n             showCancelButton: true,\n             cancelButtonText: 'Cancel',"
        },
        {
          "filename": "pyproject.toml",
          "status": "modified",
          "additions": 1,
          "deletions": 1,
          "changes": 2,
          "patch": "@@ -1,6 +1,6 @@\n [tool.poetry]\n name = \"mobsf\"\n-version = \"4.2.8\"\n+version = \"4.2.9\"\n description = \"Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis.\"\n keywords = [\"mobsf\", \"mobile security framework\", \"mobile security\", \"security tool\", \"static analysis\", \"dynamic analysis\", \"malware analysis\"]\n authors = [\"Ajin Abraham <ajin@opensecurity.in>\"]"
        }
      ]
    },
    "refs": [
      {
        "url": "https://github.com/MobSF/Mobile-Security-Framework-MobSF/commit/27d165872847f5ae7417caf09f37edeeba741e1e",
        "source": "security-advisories@github.com",
        "tags": [
          "Patch"
        ]
      },
      {
        "url": "https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-5jc6-h9w7-jm3p",
        "source": "security-advisories@github.com",
        "tags": [
          "Exploit",
          "Vendor Advisory"
        ]
      }
    ],
    "CVSS": {
      "version": "3.1",
      "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:N",
      "baseScore": 8.1,
      "baseSeverity": "HIGH",
      "attackVector": "NETWORK",
      "attackComplexity": "LOW",
      "privilegesRequired": "HIGH",
      "userInteraction": "REQUIRED",
      "scope": "CHANGED",
      "confidentialityImpact": "HIGH",
      "integrityImpact": "HIGH",
      "availabilityImpact": "NONE"
    }
  })
cc_locator.locate_vul_code()