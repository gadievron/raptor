#!/usr/bin/env bash
#
# test_release_workflow.sh — simulate the release workflow against temp repo
#
# Creates a disposable git repo with synthetic commits and tags, then runs
# each workflow step's logic and asserts expected outcomes.
#
# Usage: bash .github/tests/test_release_workflow.sh
#

set -euo pipefail

# SCRIPT_DIR resolves to the repo root: .github/tests/<this> -> ../.. = repo root.
SCRIPT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
TMPDIR_BASE=$(mktemp -d)
REPO="${TMPDIR_BASE}/test-repo"
PASS=0
FAIL=0

cleanup() { rm -rf "$TMPDIR_BASE"; }
trap cleanup EXIT

# Hermetic git: the operator's global/system config (init.defaultBranch,
# commit.gpgsign, hooks, identity) must not steer this test, and nothing
# this test does can reach that config. A pre-exported GIT_DIR /
# GIT_WORK_TREE would aim every git command below — including the
# fixture init — at an operator-chosen repo, so drop them before the
# first git runs (build_repo re-exports them pinned to the fixture).
unset GIT_DIR GIT_WORK_TREE
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

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
    git init -b main "$REPO"
    # Pin EVERY subsequent git command to the fixture repo, independent of
    # cwd: if the cd below (or the init above) ever fails in a context
    # without errexit — e.g. a partial replay of these commands with $REPO
    # unset — git must die loudly ("not a git repository"), never discover
    # the real checkout by walking up from the ambient cwd. That exact
    # walk-up once wrote the test identity below into an operator
    # checkout's repo-level .git/config.
    export GIT_DIR="$REPO/.git" GIT_WORK_TREE="$REPO"
    cd "$REPO"
    git rev-parse --resolve-git-dir "$GIT_DIR" >/dev/null || {
        echo "FATAL: fixture repo missing at '$REPO' — refusing to run git" >&2
        exit 1
    }
    git config user.name "Test"
    git config user.email "test@test.com"

    # Create raptor-offset (copy real file for accurate box-width testing)
    mkdir -p "$REPO/core/startup/assets"
    cp "$SCRIPT_DIR/core/startup/assets/raptor-offset" \
       "$REPO/core/startup/assets/raptor-offset"

    # Create core/config/__init__.py with realistic VERSION lines
    mkdir -p core/config
    cat > core/config/__init__.py <<'PYEOF'
class RaptorConfig:
    VERSION = "3.0.0"
    DEFAULT_POLICY_VERSION = "v1"
    MCP_VERSION = "0.6.0"
PYEOF

    # Create CITATION.cff (semver version line, no leading 'v')
    cat > CITATION.cff <<'CFFEOF'
cff-version: 1.2.0
title: RAPTOR
version: "3.0.0"
CFFEOF

    # Create .gitattributes
    cp "$SCRIPT_DIR/.gitattributes" "$REPO/.gitattributes" 2>/dev/null || \
    cat > .gitattributes <<'ATTR'
.github/          export-ignore
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
    mkdir -p .github/workflows .vscode test docs/img
    echo "workflow" > .github/workflows/test.yml
    echo "vscode"   > .vscode/settings.json
    echo "test"     > test/test_something.py
    echo "img"      > docs/img/logo.png
    echo "conftest" > conftest.py
    echo ".env"     > .env

    # Create files that should be included. .claude/ is RUNTIME
    # surface (slash-command dispatch, skills, hooks, settings), not
    # dev tooling — a release archive without it silently loses every
    # /command and the SessionStart banner.
    echo "source" > raptor.py
    mkdir -p packages .claude/commands .claude/skills .claude/hooks \
             libexec bin core engine tiers
    echo "pkg" > packages/__init__.py
    echo "dispatch" > .claude/commands/scan.md
    echo "skill"    > .claude/skills/demo.md
    echo "hook"     > .claude/hooks/session_start.sh
    echo "settings" > .claude/settings.json
    echo "cli"      > bin/raptor
    echo "exec"     > libexec/raptor-run-lifecycle
    echo "core"     > core/__init__.py
    echo "engine"   > engine/__init__.py
    echo "tier"     > tiers/recovery.md
    echo "claude-md" > CLAUDE.md

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
    # Markdown-hostile subject: release notes interpolate commit
    # subjects into list items, so structural characters must arrive
    # defanged (md_safe) in the generated changelog.
    echo "r" >> raptor.py && git add -A
    git commit -m 'feat: escape <img> [tags] in `output`'
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

# Release notes come from the LIVE generator (release.yml runs
# `changelog-generator --top 20 --repo <owner/repo> <tag>` at the tag's
# checkout) — drive that script against the fixture repo rather than a
# replica of its logic, the same pattern as the stamp-version section.
CHANGELOG_GEN="$SCRIPT_DIR/.github/scripts/changelog-generator"

run_changelog() {
    # Usage: run_changelog <tag> [generator args...]
    # Checks out the tag first (release.yml runs at the tag's commit;
    # the generator's log range ends at HEAD), restores main after.
    local TAG="$1"; shift
    git checkout -q "$TAG"
    local OUT
    OUT=$(python3 "$CHANGELOG_GEN" --repo owner/raptor "$@" "$TAG" 2>/dev/null)
    git checkout -q main
    printf '%s\n' "$OUT"
}

stamp_version() {
    local TAG="$1"
    python3 -c "
import sys, re
tag = sys.argv[1]
ver = tag.lstrip('v')

# The banner (core/startup/assets/raptor-offset) is deliberately NOT stamped —
# it keeps a __VERSION__ placeholder and banner.py injects the live version at
# render time. The test asserts below that the release leaves it untouched.

# core/config/__init__.py VERSION
text = open('core/config/__init__.py').read()
text = re.sub(
    r'^(\s+VERSION = \")[^\"]+(\")' ,
    lambda m: m.group(1) + ver + m.group(2),
    text, count=1, flags=re.MULTILINE)
open('core/config/__init__.py', 'w').write(text)

# CITATION.cff version (semver, no leading 'v')
text = open('CITATION.cff').read()
text = re.sub(
    r'^(version: \")[^\"]+(\")',
    lambda m: m.group(1) + ver + m.group(2),
    text, count=1, flags=re.MULTILINE)
open('CITATION.cff', 'w').write(text)
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

# ── 3. Previous-tag resolution (live generator) ───────────────────────

echo "=== Previous-tag resolution ==="

# The "(since <prev>)" header pins version-order resolution, including
# the out-of-order guard: v3.1.0's previous tag is v3.0.0 even though
# v3.2.0 already exists.
assert_contains "v3.2.0 prev is v3.1.0"              "$(run_changelog v3.2.0 --raw)" "(since v3.1.0)"
assert_contains "v3.1.0 prev is v3.0.0 (not v3.2.0)" "$(run_changelog v3.1.0 --raw)" "(since v3.0.0)"

CL_FIRST=$(run_changelog v1.0.0 --raw)
assert_contains     "first release header"   "$CL_FIRST" "## What's changed in v1.0.0"
assert_not_contains "first release: no prev" "$CL_FIRST" "(since"
echo ""

# ── 4. Changelog content (live generator, raw mode) ────────────────────

echo "=== Changelog: v2.0.0 raw (all prefix types) ==="

CL=$(run_changelog v2.0.0 --raw)

assert_contains "header names prev tag"  "$CL" "## What's changed in v2.0.0 (since v1.0.0)"
assert_contains "feat in features"       "$CL" "- add scanner module"
assert_contains "fix in fixes"           "$CL" "- handle empty input gracefully"
assert_contains "security in security"   "$CL" "- fix token leak in header"
assert_contains "docs in docs"           "$CL" "- update installation guide"
assert_contains "merge commit in other"  "$CL" "Merge pull request #42"
assert_contains "compare link present"   "$CL" "https://github.com/owner/raptor/compare/v1.0.0...v2.0.0"

# Noise filtering
assert_not_contains "chore filtered"   "$CL" "bump dev dependencies"
assert_not_contains "ci filtered"      "$CL" "add CodeQL workflow"
assert_not_contains "release filtered" "$CL" "stamp v1.0.0"
assert_not_contains "test filtered"    "$CL" "add scanner unit tests"

# Prefix stripping completeness: classified subjects arrive without
# their conventional-commit prefix anywhere in the notes.
assert_not_contains "no feat: prefix leaks"     "$CL" "feat:"
assert_not_contains "no security: prefix leaks" "$CL" "security:"
assert_not_contains "no security( prefix leaks" "$CL" "security("
echo ""

echo "=== Changelog: v3.0.0 raw (scoped prefixes + sec:) ==="

CL3=$(run_changelog v3.0.0 --raw)

assert_contains "scoped feat stripped"  "$CL3" "- add network isolation"
assert_contains "sec: in security"      "$CL3" "- patch CVE-2026-1234"
assert_contains "scoped fix stripped"   "$CL3" "- correct flag parsing"
assert_not_contains "build filtered"    "$CL3" "update Dockerfile"
assert_not_contains "style filtered"    "$CL3" "reformat with black"
assert_contains "refactor in other (not filtered)" "$CL3" "- refactor: split config into modules"
assert_not_contains "no sec( prefix leaks" "$CL3" "sec("
echo ""

echo "=== Changelog: markdown escaping ==="

CL32=$(run_changelog v3.2.0 --raw)
assert_contains "angle brackets defanged" "$CL32" "&lt;img&gt;"
assert_contains "brackets escaped"        "$CL32" '\[tags\]'
assert_contains "backticks escaped"       "$CL32" '\`output\`'
assert_not_contains "raw <img> absent"    "$CL32" "<img>"
echo ""

echo "=== Changelog: v3.0.0 ranked (release.yml invocation shape) ==="

CLR=$(run_changelog v3.0.0 --top 20)
assert_contains "ranked header names prev tag" "$CLR" "## What's changed in v3.0.0 (since v2.0.0)"
assert_contains "ranked features section"      "$CLR" "### New features"
assert_contains "ranked feat present"          "$CLR" "add network isolation"
assert_contains "ranked security present"      "$CLR" "- patch CVE-2026-1234"
assert_contains "ranked fix present"           "$CLR" "- correct flag parsing"
assert_contains "ranked compare link"          "$CLR" "https://github.com/owner/raptor/compare/v2.0.0...v3.0.0"
assert_not_contains "ranked excludes refactor" "$CLR" "split config into modules"

# The terminal preview banner must never ship inside the release notes:
# release.yml captures stdout as the ``gh release --notes-file`` content
# (run_changelog mirrors that by discarding stderr). Both directions —
# the banner stays operator-visible on stderr in the workflow log.
assert_not_contains "notes exclude preview banner"   "$CLR" "Changelog preview"
assert_not_contains "notes exclude banner rule"      "$CLR" "═══"
git checkout -q v3.0.0
CLR_ERR=$(python3 "$CHANGELOG_GEN" --repo owner/raptor --top 20 v3.0.0 2>&1 >/dev/null)
git checkout -q main
assert_contains "banner still emitted on stderr" "$CLR_ERR" "Changelog preview: v3.0.0"
echo ""

# ── 5. Version stamping ────────────────────────────────────────────────

echo "=== Version stamping ==="

# Save originals
BANNER_PATH=core/startup/assets/raptor-offset
cp "$BANNER_PATH" "$BANNER_PATH.orig"
cp core/config/__init__.py core/config/__init__.py.orig
cp CITATION.cff CITATION.cff.orig

for tag in v3.1.0 v10.20.30; do
    # Restore originals
    cp "$BANNER_PATH.orig" "$BANNER_PATH"
    cp core/config/__init__.py.orig core/config/__init__.py
    cp CITATION.cff.orig CITATION.cff

    stamp_version "$tag"
    ver="${tag#v}"

    # raptor-offset: NOT stamped — placeholder must survive untouched so
    # banner.py can inject the live version at render time.
    BANNER_LINE=$(grep "Based on Claude Code" "$BANNER_PATH")
    assert_contains "raptor-offset placeholder preserved" "$BANNER_LINE" "__VERSION__"
    assert_not_contains "raptor-offset not stamped with $tag" "$BANNER_LINE" "$tag"

    # core/config/__init__.py: only VERSION changed
    CONFIG=$(cat core/config/__init__.py)
    assert_contains     "config VERSION = \"$ver\""       "$CONFIG" "VERSION = \"$ver\""
    assert_contains     "config POLICY_VERSION unchanged"  "$CONFIG" "DEFAULT_POLICY_VERSION = \"v1\""
    assert_contains     "config MCP_VERSION unchanged"     "$CONFIG" "MCP_VERSION = \"0.6.0\""

    # CITATION.cff: version stamped (semver, no leading 'v')
    CITATION=$(cat CITATION.cff)
    assert_contains     "CITATION version: \"$ver\""        "$CITATION" "version: \"$ver\""
done

# Idempotency: stamp same version twice
cp "$BANNER_PATH.orig" "$BANNER_PATH"
cp core/config/__init__.py.orig core/config/__init__.py
cp CITATION.cff.orig CITATION.cff
stamp_version "v3.1.0"
stamp_version "v3.1.0"
CONFIG=$(cat core/config/__init__.py)
assert_contains "idempotent stamp (VERSION)" "$CONFIG" 'VERSION = "3.1.0"'
assert_eq "idempotent: single VERSION line" "1" "$(grep -c '    VERSION = ' core/config/__init__.py)"

# Restore for archive test
cp "$BANNER_PATH.orig" "$BANNER_PATH"
cp core/config/__init__.py.orig core/config/__init__.py
cp CITATION.cff.orig CITATION.cff
rm -f "$BANNER_PATH.orig" core/config/__init__.py.orig CITATION.cff.orig
echo ""

# ── 5b. stamp-version script (the real one) ────────────────────────────

echo "=== stamp-version script strictness ==="

STAMP_SCRIPT="$SCRIPT_DIR/.github/scripts/stamp-version"

# Fixture README with the release banner line the script stamps.
cat > README.md <<'MDEOF'
# fixture
║             Based on Claude Code (v0.0.0)                                 ║
MDEOF
cat > pyproject.toml <<'TOMLEOF'
[project]
name = "fixture"
version = "0.0.0"
TOMLEOF
cp core/config/__init__.py core/config/__init__.py.orig
cp CITATION.cff CITATION.cff.orig

# Happy path: every present target stamps, exit 0.
if OUT=$(python3 "$STAMP_SCRIPT" v9.9.9 2>&1); then
    pass "stamp-version exits 0 with all targets present"
else
    fail "stamp-version exits 0 with all targets present (got: $OUT)"
fi
assert_contains "script stamped config"    "$(cat core/config/__init__.py)" 'VERSION = "9.9.9"'
assert_contains "script stamped CITATION"  "$(cat CITATION.cff)"            'version: "9.9.9"'
assert_contains "script stamped pyproject" "$(cat pyproject.toml)"          'version = "9.9.9"'
assert_contains "script stamped README"    "$(cat README.md)"               "(v9.9.9)"

# A present file whose pattern misses must FAIL the run and be named —
# warn-only per-file misses shipped stale versions flagged only in logs.
echo "# banner line gone" > README.md
if OUT=$(python3 "$STAMP_SCRIPT" v9.9.10 2>&1); then
    fail "stamp-version fails when README banner pattern misses"
else
    pass "stamp-version fails when README banner pattern misses"
fi
assert_contains "miss failure names README.md" "$OUT" "README.md"

# Absent pyproject.toml is an optional target — still exit 0.
cat > README.md <<'MDEOF'
║             Based on Claude Code (v0.0.0)                                 ║
MDEOF
rm -f pyproject.toml
if OUT=$(python3 "$STAMP_SCRIPT" v9.9.11 2>&1); then
    pass "stamp-version tolerates absent pyproject.toml"
else
    fail "stamp-version tolerates absent pyproject.toml (got: $OUT)"
fi

# Restore the fixture for the archive test below.
rm -f README.md pyproject.toml
cp core/config/__init__.py.orig core/config/__init__.py
cp CITATION.cff.orig CITATION.cff
rm -f core/config/__init__.py.orig CITATION.cff.orig
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
assert_file_exists "raptor-offset in archive"       "$ARCHIVE_DIR/core/startup/assets/raptor-offset"
assert_file_exists "core/config/__init__.py in archive"      "$ARCHIVE_DIR/core/config/__init__.py"
assert_file_exists "packages/ in archive"           "$ARCHIVE_DIR/packages/__init__.py"

# Runtime surface ships (the .claude/ dispatch surface was once
# export-ignored as "dev/CI" — releases lost every /command and the
# SessionStart hook; both directions pinned here against the REAL
# .gitattributes, and release.yml verifies the same set at publish).
assert_file_exists ".claude/commands in archive"    "$ARCHIVE_DIR/.claude/commands/scan.md"
assert_file_exists ".claude/skills in archive"      "$ARCHIVE_DIR/.claude/skills/demo.md"
assert_file_exists ".claude/hooks in archive"       "$ARCHIVE_DIR/.claude/hooks/session_start.sh"
assert_file_exists ".claude/settings.json in archive" "$ARCHIVE_DIR/.claude/settings.json"

# The release.yml runtime-surface verify loop, run against the
# fixture archive with the member list DERIVED from release.yml
# itself (verbatim consumption, never a copy): weakening the
# workflow's verify list fails this suite instead of drifting
# silently past it. The floor assertion pins the load-bearing
# members so an extraction bug reads as a loud failure, not an
# empty loop.
RELEASE_YML="$SCRIPT_DIR/.github/workflows/release.yml"
VERIFY_MEMBERS=$(awk '/for p in /{f=1} f{print; if (/; do/) exit}' \
    "$RELEASE_YML" | tr -d '\\' \
    | sed -e 's/.*for p in//' -e 's/; do.*//' | tr -s ' \n' ' ')
assert_contains "derived verify list carries .claude/commands" \
    "$VERIFY_MEMBERS" ".claude/commands"
assert_contains "derived verify list carries CLAUDE.md" \
    "$VERIFY_MEMBERS" "CLAUDE.md"
assert_contains "derived verify list carries libexec" \
    "$VERIFY_MEMBERS" "libexec"
VERIFY_FAIL=""
for p in $VERIFY_MEMBERS; do
    [ -e "$ARCHIVE_DIR/$p" ] || VERIFY_FAIL="$VERIFY_FAIL $p"
done
assert_eq "runtime-surface verify loop finds no gaps" "" "$VERIFY_FAIL"

# Should be excluded by .gitattributes export-ignore
assert_file_missing ".github/ excluded"             "$ARCHIVE_DIR/.github"
assert_file_missing ".vscode/ excluded"             "$ARCHIVE_DIR/.vscode"
assert_file_missing ".gitattributes excluded"       "$ARCHIVE_DIR/.gitattributes"
assert_file_missing ".env excluded"                 "$ARCHIVE_DIR/.env"
assert_file_missing "test/ excluded"                "$ARCHIVE_DIR/test"
assert_file_missing "docs/img/ excluded"            "$ARCHIVE_DIR/docs/img"
assert_file_missing "conftest.py excluded"          "$ARCHIVE_DIR/conftest.py"

# Archive ships the banner placeholder (rendered at runtime) and the stamped
# baked VERSION the placeholder falls back to when there is no .git.
ARCHIVE_BANNER=$(grep "Based on Claude Code" "$ARCHIVE_DIR/core/startup/assets/raptor-offset")
assert_contains "archive banner keeps placeholder"   "$ARCHIVE_BANNER" "__VERSION__"
ARCHIVE_CONFIG=$(cat "$ARCHIVE_DIR/core/config/__init__.py")
assert_contains "archive config has stamped version" "$ARCHIVE_CONFIG" 'VERSION = "3.0.0"'
echo ""

# ── Summary ─────────────────────────────────────────────────────────────

echo "========================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "========================================"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
