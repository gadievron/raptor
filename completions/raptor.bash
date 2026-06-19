# Bash completion for RAPTOR (the `raptor` / `bin/raptor` launcher).
#
# Install:
#   source /path/to/raptor/completions/raptor.bash
# or symlink into your bash-completion.d:
#   ln -s "$PWD/completions/raptor.bash" /etc/bash_completion.d/raptor
#
# Covers top-level modes, `project` subcommands, and the most common flags.
# Path-valued flags (--repo/--out/--binary/--sarif/--url) fall back to file
# completion. Kept as a static list (no argparse introspection) so it loads
# instantly and works without importing RAPTOR.

_raptor_complete() {
    local cur prev words cword
    _init_completion 2>/dev/null || {
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        cword=$COMP_CWORD
    }

    local modes="scan sca fuzz web agentic codeql analyze describe doctor help version --version --help"
    local project_subs="create list use none status coverage findings correlate diff merge report clean export binary annotations notes add remove rename description import help"

    # Flags that take a filesystem path → delegate to default file completion.
    case "$prev" in
        --repo|-r|--out|-o|--binary|-b|--sarif|--target|-t|--findings|--checklist)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
        --sandbox)
            COMPREPLY=( $(compgen -W "full debug network-only none" -- "$cur") )
            return 0
            ;;
    esac

    # Top-level mode (first non-flag word after the program name).
    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$modes" -- "$cur") )
        return 0
    fi

    local mode="${COMP_WORDS[1]}"

    # `raptor project <subcommand>`
    if [[ "$mode" == "project" && $cword -eq 2 ]]; then
        COMPREPLY=( $(compgen -W "$project_subs" -- "$cur") )
        return 0
    fi
    if [[ "$mode" == "help" && $cword -eq 2 ]]; then
        COMPREPLY=( $(compgen -W "$modes" -- "$cur") )
        return 0
    fi

    # Common flags for the analysis modes.
    local common_flags="--repo -r --out -o --version --help --sandbox --no-sandbox --audit --reanalyze --model --max-cost-usd --max-findings"
    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$common_flags" -- "$cur") )
        return 0
    fi

    # Otherwise default to file completion.
    COMPREPLY=( $(compgen -f -- "$cur") )
    return 0
}

complete -F _raptor_complete raptor
complete -F _raptor_complete raptor.py
