#!/usr/bin/env bash
# Provision signed Ubuntu dependencies with bounded independent mirror fallback.
set -euo pipefail
mode=${1:?expected packages or playwright}
shift
case "$mode" in
  packages) (($#)) || exit 64 ;;
  playwright) [[ $# == 1 && $1 == /* && -x $1 ]] || exit 64 ;;
  *) exit 64 ;;
esac
# Read the running Ubuntu release: do not turn a resolute runner into noble.
. /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_CODENAME:-} =~ ^[a-z][a-z0-9]*$ ]] || exit 65
[[ $(dpkg --print-architecture) == amd64 ]] || exit 65
[[ -r "/usr/share/keyrings/ubuntu-archive-keyring.gpg" ]] || exit 65
apt_work=$(mktemp -d "/tmp/raptor-ci-apt.XXXXXXXX")
trap 'rm -rf -- "$apt_work"' EXIT
# apt's unprivileged downloader must traverse this owned, source-only tree.
chmod 755 "$apt_work"
for stage in primary fallback; do
  mkdir -m 755 "$apt_work/$stage"
  stage_dir=$apt_work/$stage
  mkdir -m 755 "$stage_dir/lists"
  if [[ $stage == primary ]]; then
    archive=https://archive.ubuntu.com/ubuntu
    security=https://security.ubuntu.com/ubuntu
  else
    archive=https://mirrors.kernel.org/ubuntu
    security=$archive
  fi
  for pocket in "$VERSION_CODENAME" "$VERSION_CODENAME-updates" "$VERSION_CODENAME-security"; do
    uri=$archive
    [[ $pocket != *-security ]] || uri=$security
    printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] %s %s main restricted universe multiverse\n' "$uri" "$pocket"
  done > "$stage_dir/sources.list"
  cat > "$stage_dir/apt.conf" <<APT
Dir::Etc::sourcelist "$stage_dir/sources.list";
Dir::Etc::sourceparts "-";
Dir::State::lists "$stage_dir/lists";
Acquire::http::Timeout "20";
Acquire::https::Timeout "20";
Acquire::Retries "2";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APT::Get::AllowUnauthenticated "false";
APT
  export APT_CONFIG=$stage_dir/apt.conf
  printf 'Ubuntu dependency setup: stage=%s release=%s archive=%s\n' "$stage" "$VERSION_CODENAME" "$archive" >&2
  if apt-get -o APT::Update::Error-Mode=any update; then
    if [[ $mode == packages ]]; then
      if apt-get install -y --no-install-recommends -- "$@"; then exit 0; else status=$?; fi
    else
      # Explicit root invocation prevents Playwright crossing sudo again and
      # dropping this scoped configuration. Browser download stays separate.
      if "$1" -m playwright install-deps chromium; then exit 0; else status=$?; fi
    fi
    printf 'Ubuntu dependency setup: stage=%s install failed status=%s\n' "$stage" "$status" >&2
  else
    status=$?
    printf 'Ubuntu dependency setup: stage=%s index refresh failed status=%s\n' "$stage" "$status" >&2
  fi
done
printf 'Ubuntu dependency setup failed on both signed archive routes\n' >&2
exit "$status"
