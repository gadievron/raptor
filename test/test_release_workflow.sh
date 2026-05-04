#!/usr/bin/env bash
#
# test_release_workflow.sh — simulate the release workflow against a temp repo
#
# Creates a disposable git repo with synthetic commits and tags, then runs
# each workflow step's logic and asserts expected outcomes.
#
# Usage: bash test/test_release_workflow.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR_BASE=$(mktemp -d)
REPO="${TMPDIR_BASE}/test-repo"
PASS=0
FAIL=0

cleanup() { rm -rf "$TMPDIR_BASE"; }
trap cleanup EXIT

# ── Helpers ──────────────────────────────────────────────────────────────

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then pass "$label"
    else fail "$label (expected '$expected', got '$actual')"
    fi
}
assert_contains() {
    local label="$1" haystack="$2" needle="$3"
    if echo "$haystack" | grep -qF -- "$needle"; then pass "$label"
    else fail "$label (expected to contain '$needle')"
    fi
}
assert_not_contains() {
    local label="$1" haystack="$2" needle="$3"
    if ! echo "$haystack" | grep -qF -- "$needle"; then pass "$label"
    else fail "$label (should not contain '$needle')"
    fi
}
assert_file_exists() {
    local label="$1" path="$2"
    if [ -e "$path" ]; then pass "$label"
    else fail "$label (file not found: $path)"
    fi
}
assert_file_missing() {
    local label="$1" path="$2"
    if [ ! -e "$path" ]; then pass "$label"
    else fail "$label (file should not exist: $path)"
    fi
}

# ── Build test repo ─────────────────────────────────────────────────────

build_repo() {
    mkdir -p "$REPO"
    cd "$REPO"
    git init -b main
    git config user.name "Test"
    git config user.email "test@test.com"

    # Create raptor-offset (copy real file for accurate box-width testing)
    cp "$SCRIPT_DIR/raptor-offset" "$REPO/raptor-offset"

    # Create core/config.py with realistic VERSION lines
    mkdir -p core
    cat > core/config.py <<'PYEOF'
class RaptorConfig:
    VERSION = "3.0.0"
    DEFAULT_POLICY_VERSION = "v1"
    MCP_VERSION = "0.6.0"
PYEOF

    # Create .gitattributes
    cp "$SCRIPT_DIR/.gitattributes" "$REPO/.gitattributes" 2>/dev/null || \
    cat > .gitattributes <<'ATTR'
.github/          export-ignore
.claude/          export-ignore
.devcontainer/    export-ignore
.vscode/          export-ignore
.gitattributes    export-ignore
.env              export-ignore
*.patch           export-ignore
out/              export-ignore
codeql_dbs/       export-ignore
docs/img/         export-ignore
test/             export-ignore
conftest.py       export-ignore
ATTR

    # Create files that should be excluded from archives
    mkdir -p .github/workflows .claude .vscode test docs/img
    echo "workflow" > .github/workflows/test.yml
    echo "claude"   > .claude/settings.json
    echo "vscode"   > .vscode/settings.json
    echo "test"     > test/test_something.py
    echo "img"      > docs/img/logo.png
    echo "conftest" > conftest.py
    echo ".env"     > .env

    # Create files that should be included
    echo "source" > raptor.py
    mkdir -p packages
    echo "pkg" > packages/__init__.py

    git add -A
    git commit -m "initial commit"
    git tag v1.0.0

    # v2.0.0 commits
    echo "a" >> raptor.py && git add -A
    git commit -m "feat: add scanner module"
    echo "b" >> raptor.py && git add -A
    git commit -m "fix: handle empty input gracefully"
    echo "c" >> raptor.py && git add -A
    git commit -m "security(auth): fix token leak in header"
    echo "d" >> raptor.py && git add -A
    git commit -m "docs: update installation guide"
    echo "e" >> raptor.py && git add -A
    git commit -m "chore: bump dev dependencies"
    echo "f" >> raptor.py && git add -A
    git commit -m "ci: add CodeQL workflow"
    echo "g" >> raptor.py && git add -A
    git commit -m "release: stamp v1.0.0"
    echo "h" >> raptor.py && git add -A
    git commit -m "test: add scanner unit tests"
    echo "i" >> raptor.py && git add -A
    git commit -m "Merge pull request #42 from feature/foo"
    git tag v2.0.0

    # v3.0.0 commits
    echo "j" >> raptor.py && git add -A
    git commit -m "feat(sandbox): add network isolation"
    echo "k" >> raptor.py && git add -A
    git commit -m "sec(cve): patch CVE-2026-1234"
    echo "l" >> raptor.py && git add -A
    git commit -m "fix(cli): correct flag parsing"
    echo "m" >> raptor.py && git add -A
    git commit -m "build: update Dockerfile base image"
    echo "n" >> raptor.py && git add -A
    git commit -m "style: reformat with black"
    echo "o" >> raptor.py && git add -A
    git commit -m "refactor: split config into modules"
    git tag v3.0.0

    # v3.1.0 commits (will also create v3.2.0 first for out-of-order test)
    echo "p" >> raptor.py && git add -A
    git commit -m "feat: add web scanner"
    git tag v3.1.0

    echo "q" >> raptor.py && git add -A
    git commit -m "feat: add exploit generator"
    git tag v3.2.0
}

# ── Workflow step functions (extracted from release.yml) ─────────────────

validate_tag() {
    local TAG="$1"
    if ! echo "${TAG}" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "INVALID"
        return 1
    fi
    echo "VALID"
    return 0
}

check_on_main() {
    local TAG="$1"
    if git merge-base --is-ancestor "$TAG" main 2>/dev/null; then
        echo "ON_MAIN"
    else
        echo "NOT_ON_MAIN"
    fi
}

resolve_prev_tag() {
    local TAG="$1"
    git tag --sort=version:refname \
        | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
        | awk -v tag="${TAG}" '$0 == tag {exit} {last=$0} END {print last}'
}

generate_changelog() {
    local TAG="$1"
    local PREV_TAG
    PREV_TAG=$(resolve_prev_tag "$TAG")

    local COMMITS
    if [ -z "$PREV_TAG" ]; then
        COMMITS=$(git log --pretty=format:"%s" "$TAG")
    else
        COMMITS=$(git log --pretty=format:"%s" "${PREV_TAG}..${TAG}")
    fi

    local FEATURES FIXES SECURITY DOCS OTHER
    FEATURES=$(echo "$COMMITS" | grep -iE '^feat(\(.+\))?:' | sed -E 's/^[^:]+:[[:space:]]*/- /' || true)
    FIXES=$(echo "$COMMITS" | grep -iE '^fix(\(.+\))?:' | sed -E 's/^[^:]+:[[:space:]]*/- /' || true)
    SECURITY=$(echo "$COMMITS" | grep -iE '^(security|sec)(\(.+\))?:' | sed -E 's/^[^:]+:[[:space:]]*/- /' || true)
    DOCS=$(echo "$COMMITS" | grep -iE '^docs(\(.+\))?:' | sed -E 's/^[^:]+:[[:space:]]*/- /' || true)
    OTHER=$(echo "$COMMITS" | grep -ivE '^(feat|fix|security|sec|docs|release|chore|ci|test|build|style)(\(.+\))?:' | sed 's/^/- /' || true)

    echo "PREV_TAG=${PREV_TAG}"
    echo "---FEATURES---"
    echo "$FEATURES"
    echo "---FIXES---"
    echo "$FIXES"
    echo "---SECURITY---"
    echo "$SECURITY"
    echo "---DOCS---"
    echo "$DOCS"
    echo "---OTHER---"
    echo "$OTHER"
}

stamp_version() {
    local TAG="$1"
    python3 -c "
import sys, re
tag = sys.argv[1]
ver = tag.lstrip('v')

# raptor-offset banner
text = open('raptor-offset').read()
def replace_banner(m):
    prefix = m.group(1)
    content = prefix + tag
    pad = 76 - len(content)
    return content + ' ' * pad + '║'
text = re.sub(r'(║\s+Based on Claude Code - )\S+[^║]*║', replace_banner, text)
open('raptor-offset', 'w').write(text)

# core/config.py VERSION
text = open('core/config.py').read()
text = re.sub(
    r'^(\s+VERSION = \")[^\"]+(\")' ,
    lambda m: m.group(1) + ver + m.group(2),
    text, count=1, flags=re.MULTILINE)
open('core/config.py', 'w').write(text)
" "$TAG"
}

build_archive() {
    local TAG="$1" DEST="$2"
    local NAME="raptor-${TAG}"
    git archive --format=tar --prefix="${NAME}/" HEAD | tar -x -C "$DEST"
    echo "${DEST}/${NAME}"
}

# ── Tests ────────────────────────────────────────────────────────────────

echo "=== Building test repo ==="
build_repo
echo ""

# ── 1. Tag validation ───────────────────────────────────────────────────

echo "=== Tag validation ==="

assert_eq "valid semver tag"      "VALID"   "$(validate_tag v3.1.0)"
assert_eq "valid large semver"    "VALID"   "$(validate_tag v10.20.30)"
assert_eq "reject branch name"    "INVALID" "$(validate_tag main       2>&1 || true)"
assert_eq "reject partial semver" "INVALID" "$(validate_tag v1.2       2>&1 || true)"
assert_eq "reject pre-release"    "INVALID" "$(validate_tag v1.2.3-rc1 2>&1 || true)"
assert_eq "reject empty"          "INVALID" "$(validate_tag ''         2>&1 || true)"
echo ""

# ── 2. Provenance check ────────────────────────────────────────────────

echo "=== Tag provenance ==="

assert_eq "v3.0.0 is on main" "ON_MAIN" "$(check_on_main v3.0.0)"

# Create an off-main tag
git checkout -b side-branch
echo "side" >> raptor.py && git add -A && git commit -m "side branch commit"
git tag v99.0.0
assert_eq "v99.0.0 not on main" "NOT_ON_MAIN" "$(check_on_main v99.0.0)"
git checkout main
echo ""

# ── 3. PREV_TAG resolution ─────────────────────────────────────────────

echo "=== PREV_TAG resolution ==="

assert_eq "v3.2.0 prev is v3.1.0"              "v3.1.0" "$(resolve_prev_tag v3.2.0)"
assert_eq "v3.1.0 prev is v3.0.0 (not v3.2.0)" "v3.0.0" "$(resolve_prev_tag v3.1.0)"
assert_eq "v2.0.0 prev is v1.0.0"              "v1.0.0" "$(resolve_prev_tag v2.0.0)"
assert_eq "v1.0.0 prev is empty"               ""        "$(resolve_prev_tag v1.0.0)"
echo ""

# ── 4. Changelog content ───────────────────────────────────────────────

echo "=== Changelog: v2.0.0 (all prefix types) ==="

CL=$(generate_changelog v2.0.0)

assert_eq       "prev tag is v1.0.0"                    "PREV_TAG=v1.0.0" "$(echo "$CL" | head -1)"
assert_contains "feat in features"                      "$(echo "$CL" | sed -n '/---FEATURES---/,/---FIXES---/p')" "- add scanner module"
assert_contains "fix in fixes"                          "$(echo "$CL" | sed -n '/---FIXES---/,/---SECURITY---/p')" "- handle empty input gracefully"
assert_contains "security in security"                  "$(echo "$CL" | sed -n '/---SECURITY---/,/---DOCS---/p')" "- fix token leak in header"
assert_contains "docs in docs"                          "$(echo "$CL" | sed -n '/---DOCS---/,/---OTHER---/p')" "- update installation guide"
assert_contains "merge commit in other"                 "$(echo "$CL" | sed -n '/---OTHER---/,//p')" "- Merge pull request #42"

# Noise filtering
assert_not_contains "chore filtered from other"         "$(echo "$CL" | sed -n '/---OTHER---/,//p')" "bump dev dependencies"
assert_not_contains "ci filtered from other"            "$(echo "$CL" | sed -n '/---OTHER---/,//p')" "add CodeQL workflow"
assert_not_contains "release filtered from other"       "$(echo "$CL" | sed -n '/---OTHER---/,//p')" "stamp v1.0.0"
assert_not_contains "test filtered from other"          "$(echo "$CL" | sed -n '/---OTHER---/,//p')" "add scanner unit tests"
echo ""

echo "=== Changelog: v3.0.0 (scoped prefixes + sec:) ==="

CL3=$(generate_changelog v3.0.0)

assert_contains "scoped feat stripped"       "$(echo "$CL3" | sed -n '/---FEATURES---/,/---FIXES---/p')" "- add network isolation"
assert_contains "sec: in security"           "$(echo "$CL3" | sed -n '/---SECURITY---/,/---DOCS---/p')" "- patch CVE-2026-1234"
assert_contains "scoped fix stripped"        "$(echo "$CL3" | sed -n '/---FIXES---/,/---SECURITY---/p')" "- correct flag parsing"
assert_not_contains "build filtered"         "$(echo "$CL3" | sed -n '/---OTHER---/,//p')" "update Dockerfile"
assert_not_contains "style filtered"         "$(echo "$CL3" | sed -n '/---OTHER---/,//p')" "reformat with black"
assert_contains "refactor in other (not filtered)" "$(echo "$CL3" | sed -n '/---OTHER---/,//p')" "- refactor: split config into modules"
echo ""

echo "=== Changelog: prefix stripping completeness ==="

# Verify no raw prefixes leak through in categorised sections
CL_FEAT=$(echo "$CL" | sed -n '/---FEATURES---/,/---FIXES---/p')
assert_not_contains "no feat: prefix in features" "$CL_FEAT" "feat:"

CL_SEC=$(echo "$CL" | sed -n '/---SECURITY---/,/---DOCS---/p')
assert_not_contains "no security: prefix in security" "$CL_SEC" "security:"
assert_not_contains "no security( prefix in security" "$CL_SEC" "security("

CL3_SEC=$(echo "$CL3" | sed -n '/---SECURITY---/,/---DOCS---/p')
assert_not_contains "no sec: prefix in security"  "$CL3_SEC" "sec:"
assert_not_contains "no sec( prefix in security"  "$CL3_SEC" "sec("
echo ""

# ── 5. Version stamping ────────────────────────────────────────────────

echo "=== Version stamping ==="

# Save originals
cp raptor-offset raptor-offset.orig
cp core/config.py core/config.py.orig

for tag in v3.1.0 v10.20.30; do
    # Restore originals
    cp raptor-offset.orig raptor-offset
    cp core/config.py.orig core/config.py

    stamp_version "$tag"
    ver="${tag#v}"

    # raptor-offset: check line contains tag and is correct width
    BANNER_LINE=$(grep "Based on Claude Code" raptor-offset)
    BANNER_LEN=${#BANNER_LINE}
    assert_eq      "raptor-offset width for $tag" "77" "$BANNER_LEN"
    assert_contains "raptor-offset contains $tag" "$BANNER_LINE" "$tag"
    assert_contains "raptor-offset box intact"    "$BANNER_LINE" "║"

    # core/config.py: only VERSION changed
    CONFIG=$(cat core/config.py)
    assert_contains     "config VERSION = \"$ver\""       "$CONFIG" "VERSION = \"$ver\""
    assert_contains     "config POLICY_VERSION unchanged"  "$CONFIG" "DEFAULT_POLICY_VERSION = \"v1\""
    assert_contains     "config MCP_VERSION unchanged"     "$CONFIG" "MCP_VERSION = \"0.6.0\""
done

# Idempotency: stamp same version twice
cp raptor-offset.orig raptor-offset
cp core/config.py.orig core/config.py
stamp_version "v3.1.0"
stamp_version "v3.1.0"
BANNER_LINE=$(grep "Based on Claude Code" raptor-offset)
assert_eq "idempotent stamp width" "77" "${#BANNER_LINE}"

# Restore for archive test
cp raptor-offset.orig raptor-offset
cp core/config.py.orig core/config.py
rm -f raptor-offset.orig core/config.py.orig
echo ""

# ── 6. Archive exclusions ──────────────────────────────────────────────

echo "=== Archive exclusions ==="

# Stamp and commit so HEAD has the version
stamp_version "v3.0.0"
git add -A
git diff --cached --quiet || git commit -m "release: stamp v3.0.0"

ARCHIVE_DIR=$(build_archive v3.0.0 "$TMPDIR_BASE")

# Should be included
assert_file_exists "raptor.py in archive"           "$ARCHIVE_DIR/raptor.py"
assert_file_exists "raptor-offset in archive"       "$ARCHIVE_DIR/raptor-offset"
assert_file_exists "core/config.py in archive"      "$ARCHIVE_DIR/core/config.py"
assert_file_exists "packages/ in archive"           "$ARCHIVE_DIR/packages/__init__.py"

# Should be excluded by .gitattributes export-ignore
assert_file_missing ".github/ excluded"             "$ARCHIVE_DIR/.github"
assert_file_missing ".claude/ excluded"             "$ARCHIVE_DIR/.claude"
assert_file_missing ".vscode/ excluded"             "$ARCHIVE_DIR/.vscode"
assert_file_missing ".gitattributes excluded"       "$ARCHIVE_DIR/.gitattributes"
assert_file_missing ".env excluded"                 "$ARCHIVE_DIR/.env"
assert_file_missing "test/ excluded"                "$ARCHIVE_DIR/test"
assert_file_missing "docs/img/ excluded"            "$ARCHIVE_DIR/docs/img"
assert_file_missing "conftest.py excluded"          "$ARCHIVE_DIR/conftest.py"

# Verify stamped version is in the archive
ARCHIVE_BANNER=$(grep "Based on Claude Code" "$ARCHIVE_DIR/raptor-offset")
assert_contains "archive has stamped version"       "$ARCHIVE_BANNER" "v3.0.0"
ARCHIVE_CONFIG=$(cat "$ARCHIVE_DIR/core/config.py")
assert_contains "archive config has stamped version" "$ARCHIVE_CONFIG" 'VERSION = "3.0.0"'
echo ""

# ── Summary ─────────────────────────────────────────────────────────────

echo "========================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "========================================"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
