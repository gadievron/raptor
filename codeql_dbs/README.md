# CodeQL Databases

This directory stores CodeQL databases created during analysis. Databases are cached per repository (using SHA256 hash) to avoid recreation on repeated scans.

## Structure

```
codeql_dbs/
└── <repo_sha256_hash>/
    ├── metadata.json              # Database creation metadata
    ├── java-db/                   # Language-specific databases
    ├── python-db/
    └── javascript-db/
```

## Cache Management

- Databases are automatically reused if the repository hasn't changed
- Use `--force-db-creation` to force recreation
- Old databases are cleaned up after 7 days (configurable)
- Manual cleanup: `rm -rf codeql_dbs/<hash>/`

## Disk Space

CodeQL databases can be large (100MB - 2GB per language). Monitor disk usage:

```bash
du -sh codeql_dbs/*
```
