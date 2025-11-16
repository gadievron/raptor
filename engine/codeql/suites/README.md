# CodeQL Query Suites

This directory contains custom CodeQL query suite configurations.

## Default Suites

RAPTOR uses the official GitHub CodeQL security suites by default:

- **java**: `codeql/java-queries:codeql-suites/java-security-and-quality.qls`
- **python**: `codeql/python-queries:codeql-suites/python-security-and-quality.qls`
- **javascript**: `codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls`
- **go**: `codeql/go-queries:codeql-suites/go-security-and-quality.qls`
- **cpp**: `codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls`
- **csharp**: `codeql/csharp-queries:codeql-suites/csharp-security-and-quality.qls`
- **ruby**: `codeql/ruby-queries:codeql-suites/ruby-security-and-quality.qls`

## Extended Suites

For more comprehensive analysis, use `--extended` flag to run security-extended suites.

## Custom Suites

You can create custom query suites here. Example format:

```yaml
# custom-java-security.qls
- description: Custom Java security queries
- queries:
    - include:
        kind:
          - problem
          - path-problem
        tags contain:
          - security
          - external/cwe
- apply: max-paths=4
```

To use a custom suite:

```bash
python3 packages/codeql/agent.py \
  --repo /path/to/code \
  --language java \
  --suite engine/codeql/suites/custom-java-security.qls
```

## Suite Documentation

For more information on CodeQL query suites:
- https://docs.github.com/en/code-security/codeql-cli/using-the-codeql-cli/creating-codeql-query-suites
