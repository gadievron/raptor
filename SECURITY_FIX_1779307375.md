# 安全漏洞修复：raptor

## 发现摘要

| 漏洞类型 | 数量 |
|----------|------|
| hardcoded_url | 1 |
| hardcoded_secret | 1 |

## 漏洞详情（Top 5）

### [MEDIUM] 硬编码敏感 URL — .claude/skills/oss-forensics/github-evidence-kit/src/clients/github.py:18

**CWE**: CWE-547

**问题代码**:
```
without authentication.     """      BASE_URL = "https://api.github.com"      def __init__(self):         self._session:
```

**建议修复**:
```
# 建议修复此处代码，参考安全最佳实践
```

---
### [HIGH] 硬编码密钥/密码 — .claude/skills/oss-forensics/github-evidence-kit/src/schema/common.py:85

**CWE**: CWE-798

**问题代码**:
```
ddress"     DOMAIN = "domain"     URL = "url"     API_KEY = "api_key"     SECRET = "secret"   # ===========
```

**建议修复**:
```
# 修复前：硬编码密钥（危险！）
# API_KEY

# 修复后：使用环境变量
import os
SECRET_KEY = os.environ.get("API_KEY", "")
if not SECRET_KEY:
    raise ValueError("API_KEY environment variable is required")

```

---
## 注意事项

- 此 PR 包含安全修复，建议优先 review
- 所有修复均遵循安全编码最佳实践
- 如有疑问，请参考 OWASP 安全指南

## CLA

贡献此修复即表示您同意将代码按项目原有许可证发布。