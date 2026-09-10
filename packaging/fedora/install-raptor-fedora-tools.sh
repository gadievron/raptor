#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Bootstrap RAPTOR's native tools and project Python environment on Fedora.

set -Eeuo pipefail

readonly TARGET_FEDORA_VERSION=44

repo=""
venv=""
minimal=0
dry_run=0
skip_python=0
skip_browser=0
os_id=""
os_version=""
os_pretty_name=""
architecture=""
node_plan_message=""
sudo_cmd=()

usage() {
	cat <<'EOF'
Usage: install-raptor-fedora-tools.sh [options]

Install Fedora RPM tools and a RAPTOR project virtual environment. The script
targets Fedora 44, refuses to run on non-Fedora hosts, and filters every RPM
name through `dnf repoquery` before installation.

Options:
  --repo PATH       RAPTOR checkout (default: this script's checkout, then
                    ~/src/copilot/raptor, then $PWD)
  --venv PATH       Project virtual environment (default: <repo>/.venv)
  --minimal         Skip language ecosystems, web tools, browsers, grammar
                    wheels, and optional Python packages
  --no-python       Install Fedora RPMs only; do not create or update the venv
  --no-browser      Do not download Playwright Chromium
  --dry-run         Query repositories and show commands without installing
  -h, --help        Show this help

Full mode installs requirements-dev.txt (which includes requirements.txt),
requirements-grammars.txt, packages/web/requirements.txt, and the repository's
optional Python requirements into the project venv. It never modifies Fedora's
system Python environment. An existing Node.js major version 22 or newer is
reused when npm is also available; Fedora's Node.js 24 RPMs are requested only
when both commands are absent. Incompatible active Node.js installations are
left unchanged and reported as an error.
EOF
}

die() {
	printf 'Error: %s\n' "$*" >&2
	exit 1
}

die_usage() {
	printf 'Error: %s\n\n' "$*" >&2
	usage >&2
	exit 2
}

on_error() {
	local status=$?
	trap - ERR
	printf 'Error: Fedora bootstrap failed at line %d (exit %d).\n' \
		"${BASH_LINENO[0]:-${LINENO}}" "$status" >&2
	exit "$status"
}
trap on_error ERR

parse_args() {
	while (($#)); do
		case "$1" in
			--repo)
				(($# >= 2)) || die_usage '--repo requires a path'
				[[ -n $2 ]] || die_usage '--repo requires a non-empty path'
				repo=$2
				shift 2
				;;
			--repo=*)
				repo=${1#*=}
				[[ -n $repo ]] || die_usage '--repo requires a non-empty path'
				shift
				;;
			--venv)
				(($# >= 2)) || die_usage '--venv requires a path'
				[[ -n $2 ]] || die_usage '--venv requires a non-empty path'
				venv=$2
				shift 2
				;;
			--venv=*)
				venv=${1#*=}
				[[ -n $venv ]] || die_usage '--venv requires a non-empty path'
				shift
				;;
			--minimal)
				minimal=1
				shift
				;;
			--no-python)
				skip_python=1
				shift
				;;
			--no-browser)
				skip_browser=1
				shift
				;;
			--dry-run)
				dry_run=1
				shift
				;;
			-h|--help)
				usage
				exit 0
				;;
			*)
				die_usage "unknown option: $1"
				;;
		esac
	done
}

read_os_release() {
	local release_file release_data
	local -a release_values=()

	# The override is intentionally undocumented and exists for hermetic tests.
	release_file=${RAPTOR_FEDORA_INSTALLER_OS_RELEASE_FILE:-/etc/os-release}
	[[ $release_file == /* ]] ||
		die "OS release path must be absolute: $release_file"
	[[ -r $release_file ]] ||
		die "cannot identify the operating system; unreadable: $release_file"

	if ! release_data=$(
		set +u
		# shellcheck disable=SC1090
		source "$release_file"
		printf '%s\n' "${ID:-}" "${VERSION_ID:-}" "${PRETTY_NAME:-unknown}"
	); then
		die "failed to read operating system metadata from $release_file"
	fi
	mapfile -t release_values <<<"$release_data"

	os_id=${release_values[0]:-}
	os_version=${release_values[1]:-}
	os_pretty_name=${release_values[2]:-unknown}

	[[ $os_id == fedora ]] ||
		die "this installer requires Fedora; detected $os_pretty_name"

	if [[ $os_version != "$TARGET_FEDORA_VERSION" ]]; then
		printf 'Warning: this bootstrap targets Fedora %s; detected Fedora %s. RPM availability will still be queried dynamically.\n' \
			"$TARGET_FEDORA_VERSION" "${os_version:-unknown}" >&2
	fi
}

is_raptor_checkout() {
	local candidate=$1 required
	local -a required_files=(
		raptor.py
		requirements.txt
	)

	[[ -d $candidate ]] || return 1
	for required in "${required_files[@]}"; do
		[[ -f $candidate/$required ]] || return 1
	done
}

resolve_repo_and_venv() {
	local script_dir embedded_repo candidate

	script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
	embedded_repo=$(cd -- "$script_dir/../.." && pwd -P)

	if [[ -z $repo ]]; then
		for candidate in \
			"$embedded_repo" \
			"$HOME/src/copilot/raptor" \
			"$PWD"; do
			if is_raptor_checkout "$candidate"; then
				repo=$candidate
				break
			fi
		done
	fi

	[[ -n $repo ]] ||
		die 'RAPTOR checkout not found; pass --repo PATH'
	[[ -d $repo ]] ||
		die "RAPTOR checkout directory does not exist: $repo"
	repo=$(realpath -- "$repo")
	is_raptor_checkout "$repo" ||
		die "not a complete RAPTOR checkout: $repo"

	if [[ -z $venv ]]; then
		venv=$repo/.venv
	elif [[ $venv != /* ]]; then
		venv=$PWD/$venv
	fi
	venv=$(realpath -m -- "$venv")

	((skip_python)) && return

	[[ $venv != / && $venv != "$repo" ]] ||
		die "refusing unsafe virtual environment path: $venv"
	[[ ! -e $venv || -d $venv ]] ||
		die "virtual environment path is not a directory: $venv"
	if [[ -d $venv && ! -f $venv/pyvenv.cfg ]]; then
		die "existing virtual environment path lacks pyvenv.cfg: $venv"
	fi
}

validate_requirement_files() {
	local requirement_name=$1 item
	local -n requirement_ref=$requirement_name

	for item in "${requirement_ref[@]}"; do
		[[ -f $repo/$item ]] ||
			die "selected Python requirements file is missing: $repo/$item"
	done
}

get_effective_uid() {
	printf '%s\n' "$EUID"
}

get_host_architecture() {
	uname -m
}

find_host_executable() {
	type -P "$1"
}

read_host_node_version() {
	"$1" --version
}

read_host_npm_version() {
	"$1" --version
}

trim_whitespace() {
	local value=$1

	value=${value#"${value%%[![:space:]]*}"}
	value=${value%"${value##*[![:space:]]}"}
	printf '%s\n' "$value"
}

fail_node_migration() {
	local reason=$1 node_path=${2:-} npm_path=${3:-}

	printf 'Error: incompatible Node.js installation: %s\n' "$reason" >&2
	printf '%s\n' \
		'Full mode requires an active Node.js major version >=22 with npm.' \
		'This installer will not use dnf --allowerasing or change the active alternative automatically.' \
		'Resolve the existing installation explicitly, then rerun. For Fedora RPM-managed tools:' >&2
	if [[ -n $node_path && -n $npm_path ]]; then
		printf '  rpm -qf %q %q\n' "$node_path" "$npm_path" >&2
	elif [[ -n $node_path ]]; then
		printf '  rpm -qf %q\n' "$node_path" >&2
	elif [[ -n $npm_path ]]; then
		printf '  rpm -qf %q\n' "$npm_path" >&2
	fi
	printf '%s\n' \
		'  sudo dnf remove PACKAGE_NAME...' \
		'  sudo dnf install nodejs24 nodejs24-bin nodejs24-npm' >&2
	exit 1
}

plan_node_dependencies() {
	local package_name=$1
	local node_path="" npm_path="" node_version="" npm_version="" node_major
	# shellcheck disable=SC2034  # Written through this nameref by design.
	local -n package_ref=$package_name

	if node_path=$(find_host_executable node 2>/dev/null); then
		[[ -n $node_path ]] ||
			fail_node_migration 'the active node path is empty'
	fi
	if npm_path=$(find_host_executable npm 2>/dev/null); then
		[[ -n $npm_path ]] ||
			fail_node_migration 'the active npm path is empty' "$node_path"
	fi

	if [[ -z $node_path && -z $npm_path ]]; then
		# shellcheck disable=SC2034  # Assignment updates the referenced array.
		package_ref=(nodejs24 nodejs24-bin nodejs24-npm)
		node_plan_message='no existing Node.js or npm detected; requesting Fedora Node.js 24 RPMs'
		return
	fi
	if [[ -z $node_path ]]; then
		fail_node_migration \
			"npm exists at $npm_path, but node is absent" "" "$npm_path"
	fi
	if [[ -z $npm_path ]]; then
		fail_node_migration \
			"node exists at $node_path, but npm is absent" "$node_path"
	fi

	if ! node_version=$(read_host_node_version "$node_path"); then
		fail_node_migration \
			"could not execute $node_path --version" "$node_path" "$npm_path"
	fi
	node_version=$(trim_whitespace "$node_version")
	if [[ ! $node_version =~ ^v?([0-9]+)([.]|$) ]]; then
		fail_node_migration \
			"could not parse version '$node_version' from $node_path" \
			"$node_path" "$npm_path"
	fi
	node_major=${BASH_REMATCH[1]}
	if ((10#$node_major < 22)); then
		fail_node_migration \
			"$node_path reports $node_version (major $node_major)" \
			"$node_path" "$npm_path"
	fi

	if ! npm_version=$(read_host_npm_version "$npm_path"); then
		fail_node_migration \
			"could not execute $npm_path --version" "$node_path" "$npm_path"
	fi
	npm_version=$(trim_whitespace "$npm_version")
	[[ -n $npm_version ]] ||
		fail_node_migration \
			"$npm_path returned an empty version" "$node_path" "$npm_path"

	node_plan_message="using existing Node.js $node_version at $node_path with npm $npm_version at $npm_path; Fedora Node.js 24 RPMs omitted"
}

prepare_privilege_command() {
	local effective_uid

	if ! effective_uid=$(get_effective_uid); then
		die 'could not determine the effective user ID'
	fi
	[[ $effective_uid =~ ^[0-9]+$ ]] ||
		die "invalid effective user ID: $effective_uid"

	if [[ $effective_uid == 0 ]]; then
		if ((skip_python == 0)); then
			die 'do not run this installer with sudo or as root while Python setup is enabled. Run it as your regular user; the script invokes sudo only for RPM installation. Root invocation is supported only with --no-python for RPM-only setup.'
		fi
		sudo_cmd=()
	else
		sudo_cmd=(sudo)
		if ((dry_run == 0)) && ! command -v sudo >/dev/null 2>&1; then
			die 'sudo is required for Fedora RPM installation'
		fi
	fi
}

filter_rpm_packages() {
	local requested_name=$1 available_name=$2 unavailable_name=$3
	local query_output package
	local -n requested_ref=$requested_name
	local -n available_ref=$available_name
	local -n unavailable_ref=$unavailable_name
	local -A repository_names=()
	local -A seen=()

	if ! query_output=$(
		dnf -q repoquery --available --qf '%{name}\n' \
			"${requested_ref[@]}"
	); then
		die 'dnf repoquery failed; check Fedora repository configuration and network access'
	fi

	while IFS= read -r package; do
		[[ -n $package ]] && repository_names["$package"]=1
	done <<<"$query_output"

	for package in "${requested_ref[@]}"; do
		[[ -n ${seen[$package]+present} ]] && continue
		seen["$package"]=1
		if [[ -n ${repository_names[$package]+present} ]]; then
			available_ref+=("$package")
		else
			unavailable_ref+=("$package")
		fi
	done
}

print_shell_command() {
	printf '  '
	printf '%q ' "$@"
	printf '\n'
}

print_rpm_plan() {
	local available_name=$1 unavailable_name=$2
	# shellcheck disable=SC2178  # These names intentionally reference arrays.
	local -n available_ref=$available_name
	# shellcheck disable=SC2178
	local -n unavailable_ref=$unavailable_name

	printf '\nNative RPM dependency plan:\n'
	printf '  Available (%d):\n' "${#available_ref[@]}"
	if ((${#available_ref[@]})); then
		printf '    %s\n' "${available_ref[@]}"
	else
		printf '    (none)\n'
	fi

	printf '  Unavailable for this release/architecture (%d):\n' \
		"${#unavailable_ref[@]}"
	if ((${#unavailable_ref[@]})); then
		printf '    %s\n' "${unavailable_ref[@]}"
	else
		printf '    (none)\n'
	fi
}

print_python_plan() {
	local requirement_name=$1 spec_name=$2 skipped_name=$3
	local -n requirement_ref=$requirement_name
	local -n spec_ref=$spec_name
	local -n skipped_ref=$skipped_name
	local item

	printf '\nPython dependency plan:\n'
	if ((skip_python)); then
		printf '  Disabled by --no-python; Fedora system Python will not be modified.\n'
		return
	fi

	printf '  Project venv: %s\n' "$venv"
	printf '  Requirement files:\n'
	for item in "${requirement_ref[@]}"; do
		printf '    %s\n' "$item"
	done
	printf '  Additional pinned packages:\n'
	for item in "${spec_ref[@]}"; do
		printf '    %s\n' "$item"
	done
	if ((${#skipped_ref[@]})); then
		printf '  Unavailable/skipped for architecture %s:\n' "$architecture"
		for item in "${skipped_ref[@]}"; do
			printf '    %s\n' "$item"
		done
	fi
	if ((minimal)); then
		printf '  Minimal mode omits grammar, web, and optional Python packages.\n'
	elif ((skip_browser)); then
		printf '  Playwright Chromium download disabled by --no-browser.\n'
	else
		printf '  Playwright Chromium will be installed into its user cache.\n'
	fi
}

print_dry_run_commands() {
	local available_name=$1 requirement_name=$2 spec_name=$3
	# shellcheck disable=SC2178  # This name intentionally references an array.
	local -n available_ref=$available_name
	local -n requirement_ref=$requirement_name
	local -n spec_ref=$spec_name
	local item

	printf '\nDry-run commands (not executed):\n'
	print_shell_command "${sudo_cmd[@]}" dnf --refresh makecache
	print_shell_command "${sudo_cmd[@]}" dnf install -y \
		--setopt=install_weak_deps=False \
		"${available_ref[@]}"

	if ((skip_python)); then
		return
	fi

	print_shell_command python3 -m venv "$venv"
	print_shell_command "$venv/bin/python" -m pip install --upgrade \
		pip setuptools wheel
	for item in "${requirement_ref[@]}"; do
		print_shell_command "$venv/bin/python" -m pip install \
			-r "$repo/$item"
	done
	print_shell_command "$venv/bin/python" -m pip install "${spec_ref[@]}"
	if ((minimal == 0 && skip_browser == 0)); then
		print_shell_command "$venv/bin/python" -m playwright install chromium
	fi
	print_shell_command "$venv/bin/python" -m pip check
}

print_command_summary() {
	local command path

	printf '\nCurrent command summary:\n'
	for command in \
		python3 git gcc clang semgrep spatch afl-fuzz gdb rr r2 \
		frida frida-trace z3 nuclei ffuf checksec ROPgadget \
		lcov gcovr java javac mvn go rustc cargo node npm pnpm \
		ruby perl php composer gh; do
		if [[ -x $venv/bin/$command ]]; then
			printf '  %-18s %s\n' "$command" "$venv/bin/$command"
		elif path=$(command -v "$command" 2>/dev/null); then
			printf '  %-18s %s\n' "$command" "$path"
		else
			printf '  %-18s %s\n' "$command" '(not installed)'
		fi
	done
}

print_manual_notes() {
	cat <<'EOF'

Upstream-only or manual tools not installed by this script:
  - GitHub CodeQL CLI
  - Joern 4.0.458 or newer
  - Ghidra distribution (full mode installs only the pyghidra bridge)
  - Google Cloud SDK and bq
  - Claude Code and GitHub Copilot CLI
  - Ollama and model weights
  - SAGE sidecar and embedding model
  - frida-server on target devices
  - Gradle (not currently packaged in Fedora 44 repositories)
  - angr (use a separate venv because its claripy/z3 constraints conflict
    with RAPTOR's main z3-solver pin)

Licensing and authentication caveats:
  - CodeQL CLI is governed by separate GitHub license terms. Confirm that
    your use is licensed before downloading it.
  - GitHub CLI may be installed as an RPM, but authentication is manual.
    Copilot CLI and Claude Code also require their own account, subscription,
    and sign-in steps.
  - Full mode installs cloud and LLM client SDKs, not credentials. Provider
    accounts, API credentials, cloud projects, and billing remain manual.
  - Upstream downloads, including Playwright Chromium, carry their own
    licenses and terms. Review them before use.
  - This script does not request, read, store, or print credentials.
EOF

	if ((skip_python)); then
		printf '\nPython environment setup was skipped by --no-python.\n'
	else
		printf '\nActivate RAPTOR'\''s environment:\n  source %q\n' \
			"$venv/bin/activate"
		printf '\nThen verify the installation:\n  cd %q\n' "$repo"
		printf '  python -m core.startup.doctor\n'
	fi
	cat <<'EOF'

rr may additionally require:
  sudo sysctl kernel.perf_event_paranoid=1
EOF
}

main() {
	local venv_python item
	local -a core_rpm_packages=(
		python3 python3-pip python3-devel python3-virtualenv pipx
		git git-lfs curl wget2-wget jq ripgrep fd-find which
		unzip zip tar gzip bzip2 xz file
		make cmake ninja-build meson autoconf automake libtool
		pkgconf-pkg-config
		gcc gcc-c++ gcc-gfortran clang clang-tools-extra llvm lld compiler-rt
		binutils elfutils elfutils-libelf-devel
		openssl openssl-devel libffi-devel zlib-ng-compat-devel
		libxml2-devel libxslt-devel capnproto capnproto-devel
		shadow-utils util-linux-core bubblewrap slirp4netns iproute nftables
		socat
		gdb lldb rr radare2 checksec python3-ROPGadget patchelf qemu-user
		valgrind strace ltrace perf graphviz
		american-fuzzy-lop american-fuzzy-lop-clang lcov gcovr
		coccinelle yara yara-devel ShellCheck
	)
	local -a full_rpm_packages=(
		nuclei ffuf
		chromium chromium-headless nss atk at-spi2-atk gtk3
		libXcomposite libXdamage libXrandr mesa-libgbm alsa-lib pango cairo
		cups-libs
		java-25-openjdk-devel maven ant
		golang delve
		rust cargo rustfmt
		yarnpkg pnpm
		ruby ruby-devel rubygem-bundler perl
		php-cli composer
		sqlite sqlite-devel
		gh
	)
	local -a rpm_packages=()
	local -a available_rpm_packages=()
	# shellcheck disable=SC2034  # Populated through a nameref in filter_rpm_packages.
	local -a unavailable_rpm_packages=()
	local -a node_rpm_packages=()
	local -a python_requirement_files=(requirements-dev.txt)
	local -a python_specs=(semgrep==1.172.0)
	local -a skipped_python_specs=()

	parse_args "$@"
	read_os_release
	resolve_repo_and_venv

	prepare_privilege_command
	if ! architecture=$(get_host_architecture); then
		die 'could not determine the host architecture'
	fi
	[[ -n $architecture ]] ||
		die 'host architecture was empty'
	if ((minimal == 0)); then
		plan_node_dependencies node_rpm_packages
	fi
	command -v dnf >/dev/null 2>&1 ||
		die 'dnf is required on Fedora'

	rpm_packages=("${core_rpm_packages[@]}")
	if ((minimal == 0)); then
		rpm_packages+=("${full_rpm_packages[@]}")
		rpm_packages+=("${node_rpm_packages[@]}")
		python_requirement_files+=(
			requirements-grammars.txt
			packages/web/requirements.txt
			.devcontainer/requirements-all-optional.txt
		)
		python_specs+=(
			frida-tools==14.10.4
			pwntools==4.15.0
		)
		if [[ $architecture == x86_64 ]]; then
			python_specs+=(atheris==3.1.0)
		else
			skipped_python_specs+=(
				"atheris==3.1.0 (unsupported on $architecture)"
			)
		fi
		python_specs+=(
			h2==4.4.1
			orjson==3.11.9
			cvss==3.6
		)
	fi
	if ((skip_python == 0)); then
		validate_requirement_files python_requirement_files
	fi

	filter_rpm_packages \
		rpm_packages available_rpm_packages unavailable_rpm_packages

	printf 'Fedora host: %s\n' "$os_pretty_name"
	printf 'Host architecture: %s\n' "$architecture"
	if ((minimal == 0)); then
		printf 'Node.js dependency plan: %s\n' "$node_plan_message"
	fi
	printf 'RAPTOR checkout: %s\n' "$repo"
	print_rpm_plan available_rpm_packages unavailable_rpm_packages
	print_python_plan \
		python_requirement_files python_specs skipped_python_specs

	((${#available_rpm_packages[@]})) ||
		die 'none of the requested RPM packages are available'

	if ((dry_run)); then
		print_dry_run_commands \
			available_rpm_packages python_requirement_files python_specs
		print_manual_notes
		return
	fi

	printf '\nRefreshing Fedora repository metadata...\n'
	"${sudo_cmd[@]}" dnf --refresh makecache

	printf 'Installing available native RPM tools...\n'
	"${sudo_cmd[@]}" dnf install -y \
		--setopt=install_weak_deps=False \
		"${available_rpm_packages[@]}"

	if ((skip_python == 0)); then
		printf '\nCreating or updating project venv: %s\n' "$venv"
		python3 -m venv "$venv"
		venv_python=$venv/bin/python
		[[ -x $venv_python ]] ||
			die "virtual environment Python was not created: $venv_python"

		"$venv_python" -m pip install --upgrade pip setuptools wheel
		for item in "${python_requirement_files[@]}"; do
			"$venv_python" -m pip install -r "$repo/$item"
		done
		"$venv_python" -m pip install "${python_specs[@]}"

		if ((minimal == 0 && skip_browser == 0)); then
			printf '\nInstalling Playwright Chromium...\n'
			"$venv_python" -m playwright install chromium
		fi

		"$venv_python" -m pip check
	fi

	print_command_summary
	print_manual_notes
	printf '\nFedora host bootstrap completed successfully.\n'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
	main "$@"
fi
