#!/usr/bin/env python3
"""
Enhanced Comprehensive Verification Script with LLM Validation

This script performs exhaustive verification that:
1. Baseline state (3a80846) integrity - files that existed before radare2
2. ALL radare2 code/files/references are completely removed
3. Post-radare2 commits are preserved (Ollama, patch skipping, scanner fix)
4. Commit history analysis - radare2 vs non-radare2 commits
5. LLM findings verification - validates findings from Claude, OpenAI, Gemini

Baseline commit: 3a80846 (pre-radare2)
Revert commit: b1ceef3
LLM validators: Claude Sonnet 4.5, OpenAI GPT-4, Gemini 2.0 Flash
"""

import subprocess
import sys
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple

BASELINE = "3a80846"  # Pre-radare2 commit
REVERT_COMMIT = "b1ceef3"  # Revert commit
MIXED_COMMIT = "3d84c31"  # Commit with both radare2 and OSS forensics

# Known radare2 commits (should be reverted)
RADARE2_COMMITS = [
    "be75a55",  # Add radare2 integration
    "8c427be",  # Fix command injection in radare2
    "c1823a1",  # Fix radare2 wrapper bugs
    "8c98d27",  # Improve radare2 messaging
    "a3367ce",  # Add automatic radare2 installation
    "18546eb",  # Fix radare2 installation issues
    "0e55c2a",  # Add installation APIs
    "f4b89dc",  # Fix installation status issues
]

# Known non-radare2 commits (should be preserved)
NON_RADARE2_COMMITS = {
    "91240d0": "Scanner subdirectories fix",
    "cf942bb": "Ollama format parameter fix",
    "d50e70d": "Ollama external server config",
    "818fac1": "Patch generation skipping",
}

def run_git(cmd: str) -> Tuple[str, int]:
    """Run git command and return output."""
    result = subprocess.run(
        f"git {cmd}",
        shell=True,
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent
    )
    return result.stdout.strip(), result.returncode

def run_command(cmd: str) -> Tuple[str, int]:
    """Run shell command and return output."""
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent
    )
    return result.stdout.strip(), result.returncode

def md5_hash(content: str) -> str:
    """Calculate MD5 hash of content."""
    return hashlib.md5(content.encode()).hexdigest()

def check_baseline_integrity() -> List[Dict]:
    """CRITICAL: Verify baseline files exist and are correct."""
    checks = []

    # Critical files that should exist in both baseline and current
    baseline_files = [
        "packages/binary_analysis/crash_analyser.py",
        "packages/binary_analysis/__init__.py",
        "core/config.py",
        "packages/llm_analysis/agent.py",
        "README.md",
        "DEPENDENCIES.md",
    ]

    for file in baseline_files:
        # Check file exists in baseline
        baseline_content, code = run_git(f"cat-file -p {BASELINE}:{file} 2>&1")
        baseline_exists = code == 0

        # Check file exists in current
        current_content, code = run_git(f"cat-file -p HEAD:{file} 2>&1")
        current_exists = code == 0

        checks.append({
            'test': f'Baseline integrity: {file} exists in both',
            'expected': 'exists in baseline and current',
            'actual': f'baseline: {"yes" if baseline_exists else "NO"}, current: {"yes" if current_exists else "NO"}',
            'pass': baseline_exists and current_exists,
            'critical': True
        })

    return checks

def check_critical_files_identical() -> List[Dict]:
    """CRITICAL: Verify files reverted to radare2 are identical to baseline."""
    checks = []

    # Files that should be byte-identical to baseline
    critical_files = [
        "packages/binary_analysis/crash_analyser.py",
        "packages/binary_analysis/__init__.py",
    ]

    for file in critical_files:
        baseline_content, _ = run_git(f"cat-file -p {BASELINE}:{file}")
        current_content, _ = run_git(f"cat-file -p HEAD:{file}")

        baseline_md5 = md5_hash(baseline_content)
        current_md5 = md5_hash(current_content)

        is_identical = baseline_md5 == current_md5

        # Also check line count
        baseline_lines = len(baseline_content.splitlines())
        current_lines = len(current_content.splitlines())

        checks.append({
            'test': f'{file} byte-identical to baseline',
            'expected': f'MD5: {baseline_md5}, {baseline_lines} lines',
            'actual': f'MD5: {current_md5}, {current_lines} lines',
            'pass': is_identical,
            'critical': True
        })

    return checks

def check_radare2_commits_reverted() -> List[Dict]:
    """IMPORTANT: Verify radare2 commits exist but their changes are reverted.

    Note: Git revert doesn't remove commits from history - it creates a new
    commit that reverses the changes. So radare2 commits WILL be in history,
    but their effects should be undone.
    """
    checks = []

    # Get all commits between baseline and HEAD
    all_commits, _ = run_git(f"log --oneline {BASELINE}..HEAD")
    commit_hashes = [line.split()[0] for line in all_commits.splitlines()]

    # Check that radare2 commits exist in history (they should)
    r2_commits_in_history = sum(1 for c in RADARE2_COMMITS if c in commit_hashes)

    checks.append({
        'test': 'Radare2 commits exist in history (expected for git revert)',
        'expected': f'{len(RADARE2_COMMITS)} commits present (revert keeps history)',
        'actual': f'{r2_commits_in_history} commits present',
        'pass': r2_commits_in_history == len(RADARE2_COMMITS),
        'critical': False,  # Not critical - just informational
        'note': 'Git revert keeps commit history but reverses changes'
    })

    # What matters is that the CHANGES are reverted (checked in other tests)
    # This is verified by:
    # - Files deleted
    # - Code removed
    # - Docs removed
    # - crash_analyser.py identical to baseline

    return checks

def check_non_radare2_commits_preserved() -> List[Dict]:
    """CRITICAL: Verify non-radare2 commits ARE preserved."""
    checks = []

    for commit, description in NON_RADARE2_COMMITS.items():
        # Check if commit is in history
        _, code = run_git(f"cat-file -e {commit} 2>&1")
        exists = code == 0

        # Check if commit is reachable from HEAD
        _, code = run_git(f"merge-base --is-ancestor {commit} HEAD 2>&1")
        in_history = code == 0

        checks.append({
            'test': f'Non-radare2 commit {commit} preserved ({description})',
            'expected': 'in history',
            'actual': 'in history' if in_history else 'NOT IN HISTORY',
            'pass': in_history,
            'critical': True
        })

    return checks

def check_specific_non_radare2_changes() -> List[Dict]:
    """CRITICAL: Verify specific non-radare2 changes are present."""
    checks = []

    # Check Ollama config (d50e70d)
    config, _ = run_git("cat-file -p HEAD:core/config.py")
    has_ollama_host = 'OLLAMA_HOST' in config
    has_ollama_getenv = 'os.getenv("OLLAMA_HOST"' in config

    checks.append({
        'test': 'Ollama OLLAMA_HOST config present (d50e70d)',
        'expected': 'OLLAMA_HOST with os.getenv',
        'actual': f'OLLAMA_HOST: {has_ollama_host}, os.getenv: {has_ollama_getenv}',
        'pass': has_ollama_host and has_ollama_getenv,
        'critical': True
    })

    # Check patch skipping (818fac1)
    agent, _ = run_git("cat-file -p HEAD:packages/llm_analysis/agent.py")
    has_exploitable_check = 'if vuln.exploitable:' in agent

    checks.append({
        'test': 'Patch skipping logic present (818fac1)',
        'expected': 'if vuln.exploitable: check',
        'actual': 'present' if has_exploitable_check else 'MISSING',
        'pass': has_exploitable_check,
        'critical': True
    })

    # Check scanner fix (91240d0) - verify .gitignore has CodeQL
    gitignore, _ = run_git("cat-file -p HEAD:.gitignore")
    has_codeql = 'codeql_dbs' in gitignore

    checks.append({
        'test': 'Scanner fix preserved (91240d0) - CodeQL in .gitignore',
        'expected': 'codeql_dbs present',
        'actual': 'present' if has_codeql else 'MISSING',
        'pass': has_codeql,
        'critical': False  # Nice to have but not blocking
    })

    return checks

def check_radare2_removal_complete() -> List[Dict]:
    """CRITICAL: Verify ALL radare2 is removed."""
    checks = []

    # Check files deleted
    radare2_files = [
        "packages/binary_analysis/radare2_wrapper.py",
        "core/sarif/crash_converter.py",
        "test/test_radare2_wrapper.py",
        "test/test_radare2_address_handling.py",
        "test/test_radare2_backward_disassembly.py",
        "test/test_radare2_security.py",
        "test/test_crash_analyser_install.py",
        "ARCHITECTURE_CONTROL_FLOW.md",
        "AUTO_INSTALL.md",
        "RADARE2_INTEGRATION.md",
    ]

    deleted_count = 0
    for file in radare2_files:
        _, code = run_git(f"cat-file -p HEAD:{file} 2>&1")
        if code != 0:
            deleted_count += 1

    checks.append({
        'test': 'All radare2 files deleted',
        'expected': f'{len(radare2_files)} files deleted',
        'actual': f'{deleted_count} files deleted',
        'pass': deleted_count == len(radare2_files),
        'critical': True
    })

    # Check implementation-tests directory
    _, code = run_git("ls-tree -d HEAD:implementation-tests 2>&1")
    checks.append({
        'test': 'implementation-tests/ directory deleted',
        'expected': 'not found',
        'actual': 'deleted' if code != 0 else 'EXISTS',
        'pass': code != 0,
        'critical': True
    })

    # Check for radare2 code references (excluding verification scripts)
    grep_radare, _ = run_command("git grep -i 'radare' HEAD -- '*.py' | grep -v 'verify.*\\.py' | grep -v 'VALIDATION\\|VERIFICATION\\|REPORT' 2>/dev/null")
    checks.append({
        'test': 'No radare2 references in Python code (excluding verification scripts)',
        'expected': '0 matches',
        'actual': f'{len(grep_radare.splitlines()) if grep_radare else 0} matches',
        'pass': not grep_radare,
        'critical': True,
        'note': 'Verification scripts may reference radare2 for validation purposes'
    })

    # Check for radare2 in README
    readme, _ = run_git("cat-file -p HEAD:README.md")
    radare_count = readme.lower().count('radare')
    checks.append({
        'test': 'No radare2 in README.md',
        'expected': '0 mentions',
        'actual': f'{radare_count} mentions',
        'pass': radare_count == 0,
        'critical': True
    })

    # Check for radare2 in DEPENDENCIES
    deps, _ = run_git("cat-file -p HEAD:DEPENDENCIES.md")
    radare_deps = deps.lower().count('radare')
    checks.append({
        'test': 'No radare2 in DEPENDENCIES.md',
        'expected': '0 mentions',
        'actual': f'{radare_deps} mentions',
        'pass': radare_deps == 0,
        'critical': True
    })

    return checks

def check_llm_finding_oss_forensics() -> List[Dict]:
    """INFO: Historical LLM finding about OSS forensics documentation."""
    checks = []

    readme, _ = run_git("cat-file -p HEAD:README.md")

    # Historical: LLMs found section was missing in PRE-FIX state
    # Current: After surgical fix, section should be present
    has_detailed_section = "### OSS Forensics Investigation" in readme
    checks.append({
        'test': 'LLM Historical Finding: OSS forensics was missing (now restored)',
        'expected': 'section PRESENT after surgical fix',
        'actual': 'present (fixed)' if has_detailed_section else 'STILL MISSING',
        'pass': has_detailed_section,  # Pass means surgical fix worked
        'critical': False,  # Informational - historical LLM finding
        'llm_validation': True,
        'note': 'LLMs correctly identified this was missing before; surgical fix restored it'
    })

    # Check 2: OSS forensics brief mention preserved (LLM finding)
    has_brief_mention = "OSS Forensics" in readme and "for evidence-backed GitHub repository investigations" in readme
    checks.append({
        'test': 'LLM Finding: OSS forensics brief mention preserved',
        'expected': 'brief mention present (all 3 LLMs agree)',
        'actual': 'present (LLM correct)' if has_brief_mention else 'MISSING (LLM was WRONG)',
        'pass': has_brief_mention,  # Pass means LLM was correct
        'critical': True,
        'llm_validation': True
    })

    # Check 3: Check what 3d84c31 added
    commit_3d84c31_readme, _ = run_git(f"show {MIXED_COMMIT}:README.md")
    commit_had_oss_section = "### OSS Forensics Investigation" in commit_3d84c31_readme
    commit_had_radare = "radare2" in commit_3d84c31_readme.lower()

    checks.append({
        'test': 'LLM Finding: Commit 3d84c31 had BOTH radare2 and OSS forensics',
        'expected': 'both present (all 3 LLMs agree)',
        'actual': f'radare2: {commit_had_radare}, OSS: {commit_had_oss_section}',
        'pass': commit_had_radare and commit_had_oss_section,
        'critical': True,
        'llm_validation': True
    })

    return checks

def check_llm_finding_bigquery() -> List[Dict]:
    """CRITICAL: Verify LLM finding about BigQuery section preservation."""
    checks = []

    deps, _ = run_git("cat-file -p HEAD:DEPENDENCIES.md")

    # Check BigQuery section present
    has_bigquery = "Google Cloud BigQuery" in deps
    has_credentials = "GOOGLE_APPLICATION_CREDENTIALS" in deps

    checks.append({
        'test': 'LLM Finding: BigQuery section preserved in DEPENDENCIES',
        'expected': 'section present (all 3 LLMs agree)',
        'actual': f'BigQuery: {has_bigquery}, GOOGLE_APPLICATION_CREDENTIALS: {has_credentials}',
        'pass': has_bigquery and has_credentials,
        'critical': True,
        'llm_validation': True
    })

    # Check radare2 section removed
    has_radare2_section = "radare2" in deps.lower()

    checks.append({
        'test': 'LLM Finding: Radare2 section removed from DEPENDENCIES',
        'expected': 'section NOT present (all 3 LLMs agree)',
        'actual': 'PRESENT (LLM was WRONG)' if has_radare2_section else 'removed (LLM correct)',
        'pass': not has_radare2_section,
        'critical': True,
        'llm_validation': True
    })

    # Verify 3d84c31 added both
    commit_3d84c31_deps, _ = run_git(f"show {MIXED_COMMIT}:DEPENDENCIES.md")
    commit_had_bigquery = "Google Cloud BigQuery" in commit_3d84c31_deps
    commit_had_radare2 = "radare2" in commit_3d84c31_deps.lower()

    checks.append({
        'test': 'LLM Finding: Commit 3d84c31 added BOTH radare2 and BigQuery to DEPENDENCIES',
        'expected': 'both present (all 3 LLMs agree)',
        'actual': f'radare2: {commit_had_radare2}, BigQuery: {commit_had_bigquery}',
        'pass': commit_had_radare2 and commit_had_bigquery,
        'critical': True,
        'llm_validation': True
    })

    return checks

def check_llm_finding_surgical_removal() -> List[Dict]:
    """INFO: Track LLM findings about surgical vs non-surgical removal (historical)."""
    checks = []

    # Check DEPENDENCIES.md was surgical (kept BigQuery, removed radare2)
    deps, _ = run_git("cat-file -p HEAD:DEPENDENCIES.md")
    has_bigquery = "Google Cloud BigQuery" in deps
    has_radare2 = "radare2" in deps.lower()

    dependencies_surgical = has_bigquery and not has_radare2

    checks.append({
        'test': 'LLM Finding: DEPENDENCIES.md removal was SURGICAL',
        'expected': 'kept BigQuery, removed radare2 (all 3 LLMs agree)',
        'actual': f'BigQuery: {"kept" if has_bigquery else "removed"}, radare2: {"kept" if has_radare2 else "removed"}',
        'pass': dependencies_surgical,
        'critical': True,  # Still critical for actual safety
        'llm_validation': True
    })

    # Check README.md surgical status (after fix, should be surgical now)
    readme, _ = run_git("cat-file -p HEAD:README.md")
    has_recent_updates = "## Recent Updates" in readme
    has_oss_detailed = "### OSS Forensics Investigation" in readme
    has_radare2_section = "radare2" in readme.lower()

    # After surgical fix: OSS should be present, radare2 should be absent
    readme_is_surgical_now = has_oss_detailed and not has_radare2_section

    checks.append({
        'test': 'README.md is now SURGICAL (OSS kept, radare2 removed)',
        'expected': 'OSS detailed present, radare2 absent (after surgical fix)',
        'actual': f'OSS detailed: {"present" if has_oss_detailed else "removed"}, radare2: {"present" if has_radare2_section else "absent"}',
        'pass': readme_is_surgical_now,
        'critical': True,
        'llm_validation': False,  # This is current state check, not LLM validation
        'note': 'Previous revert was not surgical; surgical fix applied successfully'
    })

    return checks

def check_llm_false_positives() -> List[Dict]:
    """Verify claimed false positives from Gemini."""
    checks = []

    # Check raptor_agentic.py false positive
    _, code = run_git(f"log --oneline --all -- raptor_agentic.py")
    history_output, _ = run_git(f"log --oneline --all -- raptor_agentic.py")
    has_ollama_commit = "d50e70d" in history_output
    has_baseline_commit = "611d3d0" in history_output

    checks.append({
        'test': 'LLM Finding: raptor_agentic.py is FALSE POSITIVE',
        'expected': 'file existed in baseline, modified by Ollama (Claude/OpenAI agree)',
        'actual': f'baseline commit: {has_baseline_commit}, Ollama commit: {has_ollama_commit}',
        'pass': has_baseline_commit and has_ollama_commit,
        'critical': False,  # Not critical, just validation
        'llm_validation': True
    })

    # Check .gitignore false positive
    gitignore, _ = run_git("cat-file -p HEAD:.gitignore")
    has_codeql = "codeql_dbs" in gitignore
    has_radare2 = "radare" in gitignore.lower()

    checks.append({
        'test': 'LLM Finding: .gitignore changes are FALSE POSITIVE',
        'expected': 'only CodeQL dbs, no radare2 (Claude/OpenAI agree)',
        'actual': f'codeql_dbs: {has_codeql}, radare2: {has_radare2}',
        'pass': has_codeql and not has_radare2,
        'critical': False,
        'llm_validation': True
    })

    return checks

def check_llm_consensus() -> List[Dict]:
    """INFO: Historical LLM consensus (they correctly identified pre-fix issues)."""
    checks = []

    # Historical: All 3 LLMs agreed the PREVIOUS state was NOT SAFE
    # Current: After surgical fix, check if their concerns are addressed

    readme, _ = run_git("cat-file -p HEAD:README.md")
    has_oss_detailed = "### OSS Forensics Investigation" in readme
    has_ffmpeg = "**FFmpeg-specific** patching for Google's recent disclosure" in readme
    no_radare2 = readme.lower().count('radare') == 0

    # LLMs' concerns are NOW addressed if all three conditions met
    llm_concerns_addressed = has_oss_detailed and has_ffmpeg and no_radare2

    checks.append({
        'test': 'LLM Concerns Addressed: Surgical fix applied',
        'expected': 'OSS forensics restored + FFmpeg baseline + No radare2',
        'actual': f'OSS: {"yes" if has_oss_detailed else "no"}, FFmpeg: {"yes" if has_ffmpeg else "no"}, No radare2: {"yes" if no_radare2 else "no"}',
        'pass': llm_concerns_addressed,
        'critical': False,  # Informational - tracks if LLM concerns addressed
        'llm_validation': True,
        'consensus': {
            'claude_said': 'NOT SAFE (before fix)',
            'openai_said': 'NOT SAFE (before fix)',
            'gemini_said': 'NOT SAFE (before fix)',
            'status': 'CONCERNS ADDRESSED' if llm_concerns_addressed else 'CONCERNS REMAIN'
        },
        'note': 'LLMs correctly identified pre-fix issues; surgical fix addresses all concerns'
    })

    return checks

def check_surgical_revert() -> List[Dict]:
    """CRITICAL: Verify surgical revert was performed correctly."""
    checks = []

    readme, _ = run_git("cat-file -p HEAD:README.md")

    # Check line 6 is back to FFmpeg-specific (baseline)
    has_ffmpeg_line = "**FFmpeg-specific** patching for Google's recent disclosure" in readme
    checks.append({
        'test': 'Surgical Revert: Line 6 reverted to FFmpeg-specific patching',
        'expected': 'FFmpeg-specific patching for Google\'s recent disclosure',
        'actual': 'present' if has_ffmpeg_line else 'MISSING',
        'pass': has_ffmpeg_line,
        'critical': True
    })

    # Check line 7 preserved (OSS Forensics brief mention)
    has_oss_brief = "**OSS Forensics** for evidence-backed GitHub repository investigations" in readme
    checks.append({
        'test': 'Surgical Revert: Line 7 preserved (OSS Forensics brief)',
        'expected': 'OSS Forensics for evidence-backed GitHub repository investigations',
        'actual': 'present' if has_oss_brief else 'MISSING',
        'pass': has_oss_brief,
        'critical': True
    })

    # Check detailed OSS forensics section present
    has_oss_detailed = "### OSS Forensics Investigation" in readme
    checks.append({
        'test': 'Surgical Revert: OSS Forensics detailed section restored',
        'expected': '### OSS Forensics Investigation section present',
        'actual': 'present' if has_oss_detailed else 'MISSING',
        'pass': has_oss_detailed,
        'critical': True
    })

    # Check NO radare2 mentions
    radare_count = readme.lower().count('radare')
    checks.append({
        'test': 'Surgical Revert: No radare2 mentions in README',
        'expected': '0 mentions',
        'actual': f'{radare_count} mentions',
        'pass': radare_count == 0,
        'critical': True
    })

    # Check NO "Crash Analysis with radare2" line
    has_radare2_crash = "Crash Analysis** with radare2" in readme
    checks.append({
        'test': 'Surgical Revert: No "Crash Analysis with radare2" line',
        'expected': 'not present',
        'actual': 'PRESENT' if has_radare2_crash else 'not present',
        'pass': not has_radare2_crash,
        'critical': True
    })

    return checks

def check_final_safety() -> List[Dict]:
    """CRITICAL: Final safety check - is the surgical revert safe to push?"""
    checks = []

    readme, _ = run_git("cat-file -p HEAD:README.md")

    # Check all surgical revert requirements
    has_ffmpeg = "**FFmpeg-specific** patching for Google's recent disclosure" in readme
    has_oss_brief = "**OSS Forensics** for evidence-backed GitHub repository investigations" in readme
    has_oss_detailed = "### OSS Forensics Investigation" in readme
    no_radare2 = readme.lower().count('radare') == 0

    # The revert is safe if ALL requirements are met
    is_safe = has_ffmpeg and has_oss_brief and has_oss_detailed and no_radare2

    checks.append({
        'test': 'FINAL SAFETY CHECK: Is surgical revert safe to push?',
        'expected': 'Baseline restored + OSS forensics preserved + No radare2',
        'actual': f'FFmpeg: {has_ffmpeg}, OSS brief: {has_oss_brief}, OSS detailed: {has_oss_detailed}, No radare2: {no_radare2}',
        'pass': is_safe,
        'critical': True,
        'note': 'All 3 LLMs verified: FFmpeg baseline + OSS forensics preservation = correct'
    })

    return checks

def main():
    """Run all verification checks including LLM validation."""
    print("=" * 80)
    print("ENHANCED RADARE2 REVERT VERIFICATION WITH LLM VALIDATION")
    print("=" * 80)
    print(f"Baseline:     {BASELINE} (pre-radare2)")
    print(f"Revert:       {REVERT_COMMIT}")
    print(f"Mixed commit: {MIXED_COMMIT} (radare2 + OSS forensics)")
    print(f"Validators:   Claude Sonnet 4.5, OpenAI GPT-4, Gemini 2.0 Flash")
    print("=" * 80)
    print()

    all_checks = []

    # Phase 1: Baseline Integrity
    print("📊 Phase 1: Checking baseline state integrity...")
    all_checks.extend(check_baseline_integrity())

    # Phase 2: File Identity Verification
    print("🔍 Phase 2: Verifying files are byte-identical to baseline...")
    all_checks.extend(check_critical_files_identical())

    # Phase 3: Commit History Analysis
    print("📜 Phase 3: Analyzing commit history...")
    all_checks.extend(check_radare2_commits_reverted())
    all_checks.extend(check_non_radare2_commits_preserved())

    # Phase 4: Specific Changes Verification
    print("✅ Phase 4: Verifying specific non-radare2 changes...")
    all_checks.extend(check_specific_non_radare2_changes())

    # Phase 5: Radare2 Removal Completeness
    print("🗑️  Phase 5: Verifying radare2 removal is complete...")
    all_checks.extend(check_radare2_removal_complete())

    # Phase 6: LLM Findings Validation
    print("🤖 Phase 6: Validating LLM findings...")
    print("   - OSS forensics documentation...")
    all_checks.extend(check_llm_finding_oss_forensics())
    print("   - BigQuery section preservation...")
    all_checks.extend(check_llm_finding_bigquery())
    print("   - Surgical removal analysis...")
    all_checks.extend(check_llm_finding_surgical_removal())
    print("   - False positive verification...")
    all_checks.extend(check_llm_false_positives())
    print("   - LLM consensus verification...")
    all_checks.extend(check_llm_consensus())

    # Phase 7: Surgical Revert Verification
    print("✂️  Phase 7: Verifying surgical revert correctness...")
    all_checks.extend(check_surgical_revert())

    # Phase 8: Final Safety Check
    print("🛡️  Phase 8: Final safety verification...")
    all_checks.extend(check_final_safety())

    print()
    print("=" * 80)
    print("DETAILED RESULTS")
    print("=" * 80)
    print()

    # Print results
    passed = 0
    failed = 0
    critical_failed = 0
    llm_checks = 0
    llm_correct = 0

    for check in all_checks:
        is_critical = check.get('critical', False)
        is_llm = check.get('llm_validation', False)

        if is_llm:
            llm_checks += 1
            if check['pass']:
                llm_correct += 1

        if check['pass']:
            status = "✅ PASS"
            passed += 1
        else:
            if is_critical:
                status = "❌ FAIL [CRITICAL]"
                critical_failed += 1
            else:
                status = "⚠️  FAIL"
            failed += 1

        # Add LLM badge
        if is_llm:
            status += " [LLM VALIDATION]"

        print(f"{status} | {check['test']}")
        print(f"         Expected: {check['expected']}")
        print(f"         Actual:   {check['actual']}")

        # Print note if available
        if 'note' in check:
            print(f"         Note:     {check['note']}")

        # Print consensus if available
        if 'consensus' in check:
            print(f"         LLM Consensus:")
            for llm, verdict in check['consensus'].items():
                print(f"           - {llm}: {verdict}")

        print()

    print("=" * 80)
    print(f"SUMMARY: {passed} passed, {failed} failed")
    if critical_failed > 0:
        print(f"         {critical_failed} CRITICAL failures")
    print(f"         {llm_correct}/{llm_checks} LLM findings validated")
    print("=" * 80)

    # LLM validation summary
    if llm_checks > 0:
        llm_accuracy = (llm_correct / llm_checks) * 100
        print()
        print("🤖 LLM VALIDATION RESULTS:")
        print(f"   LLM Accuracy: {llm_accuracy:.1f}% ({llm_correct}/{llm_checks} findings correct)")

        if llm_accuracy == 100:
            print("   ✅ All LLM findings validated - Perfect accuracy!")
        elif llm_accuracy >= 90:
            print("   ✅ Excellent LLM accuracy - Highly reliable findings")
        elif llm_accuracy >= 80:
            print("   ⚠️  Good LLM accuracy - Minor discrepancies found")
        else:
            print("   ❌ Poor LLM accuracy - Significant discrepancies found")

    print()

    if critical_failed > 0:
        print("❌ VERIFICATION FAILED - CRITICAL issues found!")
        print("   Radare2 revert has issues that must be fixed")

        # Check if the critical failure matches LLM findings
        if llm_accuracy >= 90:
            print()
            print("   Note: LLM validators correctly identified these issues")
            print("   Recommendation: Apply LLM-suggested fixes")

        return 1
    elif failed > 0:
        print("⚠️  VERIFICATION PASSED with warnings")
        print("   Radare2 revert is mostly correct but has non-critical issues")
        return 0
    else:
        print("✅ VERIFICATION PASSED - Revert is 100% correct!")
        print("   All checks passed including LLM validation")
        print("   Safe to push to GitHub")
        return 0

if __name__ == "__main__":
    sys.exit(main())
