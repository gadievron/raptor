#compdef raptor raptor.py
#
# Zsh completion for RAPTOR. Install by adding the completions/ dir to your
# fpath before `compinit`, e.g. in ~/.zshrc:
#   fpath=(/path/to/raptor/completions $fpath)
#   autoload -Uz compinit && compinit
#
# Mirrors completions/raptor.bash: top-level modes, `project` subcommands,
# and path/flag completion. Static (no RAPTOR import) so it loads instantly.

_raptor() {
    local -a modes project_subs
    modes=(scan sca fuzz web agentic codeql analyze describe doctor help version)
    project_subs=(create list use none status coverage findings correlate diff
                  merge report clean export binary annotations notes add remove
                  rename description import help)

    if (( CURRENT == 2 )); then
        _describe -t modes 'raptor mode' modes
        return
    fi

    case "${words[2]}" in
        project)
            if (( CURRENT == 3 )); then
                _describe -t subcommands 'project subcommand' project_subs
                return
            fi
            ;;
        help)
            if (( CURRENT == 3 )); then
                _describe -t modes 'mode' modes
                return
            fi
            ;;
    esac

    # Path/flag fallback.
    case "${words[CURRENT-1]}" in
        --repo|-r|--out|-o|--binary|-b|--sarif|--target|-t)
            _files
            return
            ;;
        --sandbox)
            compadd full debug network-only none
            return
            ;;
    esac

    if [[ "${words[CURRENT]}" == -* ]]; then
        compadd -- --repo --out --version --help --sandbox --no-sandbox \
                   --audit --reanalyze --model --max-cost-usd --max-findings
    else
        _files
    fi
}

_raptor "$@"
