# Fedora 44 and GitHub Copilot CLI

This guide sets up RAPTOR on a stock Fedora 44 workstation and launches it
through GitHub Copilot CLI. It covers native host bootstrap, authentication,
Fedora-specific caveats, and checksum-pinned recipes for optional upstream
tools.

See also:

- [Dependencies](dependencies.md) for the dependency and licence overview.
- [Troubleshooting](troubleshooting.md) for subsystem-specific failures.
- [Security](security.md) and [Sandbox](sandbox.md) for RAPTOR's containment
  model.

## Trust and authorization

RAPTOR executes scanners, build systems, generated harnesses, and sometimes
target binaries. Use it only on systems and code you are authorized to test.

- Treat a new target checkout as untrusted. Review its build files, agent
  instructions, hooks, skills, MCP configuration, and generated scripts before
  allowing execution.
- Copilot launch fails closed when a target contains agent configuration that
  could become trusted through `--add-dir`. Use `--trust-repo` only after
  reviewing the paths named by the launcher.
- Never put API keys, OAuth tokens, service-account JSON, or auth directories
  in the RAPTOR checkout. Keep credentials in their standard user-scoped
  stores or explicitly configured paths.
- rr requires the host `kernel.perf_event_paranoid` setting to be `1` or
  lower. Change kernel settings only when the analysis needs rr.


## Host workflow

### 1. Check Fedora and clone RAPTOR

Run the installer as your regular desktop user, not through `sudo`. It invokes
`sudo` only for RPM operations.

```bash
. /etc/os-release
printf 'Detected: %s %s\n' "$ID" "$VERSION_ID"
test "$ID" = fedora
test "$VERSION_ID" = 44

sudo dnf install -y git
mkdir -p "$HOME/src/copilot"
git clone https://github.com/gadievron/raptor.git \
  "$HOME/src/copilot/raptor"
cd "$HOME/src/copilot/raptor"
```

### 2. Preview the Fedora installer

The installer refuses non-Fedora hosts and warns if the Fedora release is not
44. It runs `dnf repoquery` first, so package names absent from the enabled
Fedora repositories are reported and omitted instead of making the whole RPM
transaction fail.

```bash
cd "$HOME/src/copilot/raptor"
./packaging/fedora/install-raptor-fedora-tools.sh \
  --repo "$PWD" \
  --dry-run
```

Review the available and unavailable RPM lists, the Node.js plan, the Python
requirements, and the exact commands before proceeding.

### 3. Install full or minimal host tooling

Full installation:

```bash
cd "$HOME/src/copilot/raptor"
./packaging/fedora/install-raptor-fedora-tools.sh --repo "$PWD"
```

Full installation without downloading Playwright Chromium:

```bash
cd "$HOME/src/copilot/raptor"
./packaging/fedora/install-raptor-fedora-tools.sh \
  --repo "$PWD" \
  --no-browser
```

Minimal installation:

```bash
cd "$HOME/src/copilot/raptor"
./packaging/fedora/install-raptor-fedora-tools.sh \
  --repo "$PWD" \
  --minimal
```

The minimal mode installs the core native analysis/debugging RPMs and the core
Python requirements, but skips language ecosystems, web tools, browsers,
grammar wheels, and optional Python packages.

To use a different project virtual environment:

```bash
cd "$HOME/src/copilot/raptor"
./packaging/fedora/install-raptor-fedora-tools.sh \
  --repo "$PWD" \
  --venv "$PWD/.venv-fedora"
```

RPM-only setup is the one mode permitted as root:

```bash
cd "$HOME/src/copilot/raptor"
sudo ./packaging/fedora/install-raptor-fedora-tools.sh \
  --repo "$PWD" \
  --no-python
```

Do not use `sudo` without `--no-python`. Python setup always uses
`python3 -m venv` and `<venv>/bin/python -m pip`; it never installs packages
into Fedora's system Python.

Installer options:

| Option | Effect |
|--------|--------|
| `--repo PATH` | RAPTOR checkout; defaults to the script checkout, then `~/src/copilot/raptor`, then `$PWD` |
| `--venv PATH` | Project virtual environment; defaults to `<repo>/.venv` |
| `--minimal` | Omit language ecosystems, web/browser tooling, grammar wheels, and optional Python packages |
| `--no-python` | Install available RPMs only; this is the only root-supported mode |
| `--no-browser` | Keep full mode but skip the Playwright Chromium download |
| `--dry-run` | Query repositories and print the plan without installing |

### 4. Activate and run the doctor

```bash
cd "$HOME/src/copilot/raptor"
source .venv/bin/activate
python -m pip check
python -m core.startup.doctor

export PATH="$HOME/.local/bin:$PATH"
export PATH="$PATH:$HOME/src/copilot/raptor/bin"
raptor --help
```

To persist those PATH entries for Bash:

```bash
grep -qxF 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.bashrc" ||
  printf '%s\n' 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
grep -qxF 'export PATH="$PATH:$HOME/src/copilot/raptor/bin"' "$HOME/.bashrc" ||
  printf '%s\n' \
    'export PATH="$PATH:$HOME/src/copilot/raptor/bin"' >> "$HOME/.bashrc"
```

### 5. Install and authenticate GitHub Copilot CLI

The official npm path requires Node.js 22 or later. Full installer mode reuses
an existing Node.js 22+ installation only when `npm` also works. If both
commands are absent, it requests Fedora's Node.js 24 RPMs. If only one command
exists, Node is older than 22, or either version command fails, the installer
stops with migration guidance rather than using `dnf --allowerasing` or
changing alternatives.

If you used minimal mode and do not already have Node.js 22+ with npm:

```bash
sudo dnf install -y nodejs24 nodejs24-bin nodejs24-npm
node --version
npm --version
```

Install the validated Copilot CLI version into your user prefix. Do not use
`sudo npm install -g`.

```bash
mkdir -p "$HOME/.local"
npm install --global --prefix "$HOME/.local" \
  "@github/copilot@1.0.83"
export PATH="$HOME/.local/bin:$PATH"
copilot --version
```

The npm command and Node.js 22 prerequisite are documented in the official
[Copilot CLI installation guide](https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/install-copilot-cli).
Copilot CLI requires an eligible account/subscription unless you deliberately
configure a supported BYOK mode.

Authenticate interactively:

```bash
copilot login
```

Use the device flow when a browser callback is unsuitable:

```bash
copilot login --device-code
```

See GitHub's
[Copilot CLI authentication guide](https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/authenticate-copilot-cli)
for OAuth, keychain storage, fine-grained tokens, organization policy, SSO, and
headless environments. Be aware that `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, or
`GITHUB_TOKEN` can override stored OAuth credentials.

RAPTOR keeps ordinary internal `copilotcli` provider calls stateless: each call
uses disposable private Copilot state and receives either a parent-resolved
token or validated auth-only records from the login above. CLI settings,
plugins, trusted folders, and session databases are not copied. Interactive
`raptor --copilot` sessions and an explicitly configured
`copilotcli-resumable` provider intentionally use persistent Copilot state.

### 6. Launch RAPTOR through Copilot

```bash
cd "$HOME/src/copilot/raptor"
source .venv/bin/activate
export PATH="$HOME/.local/bin:$PATH"
export PATH="$PATH:$HOME/src/copilot/raptor/bin"
raptor --copilot /absolute/path/to/target
```

Inside the Copilot session, use:

```text
/raptor-version
```

Copilot CLI reserves `/version` for itself. `/raptor-version` reports the
RAPTOR framework version on both agent CLI paths.

### What differs from stock Fedora 44

- The installer dynamically filters every requested RPM with `dnf repoquery`;
  the exact installed set depends on enabled Fedora repositories and
  architecture.
- Python dependencies live in the project `.venv`; Fedora's externally
  managed system Python is not modified.
- Full mode requires Node.js 22+ and working npm for npm-installed agent CLIs.
  Fedora Node.js 24 is requested only when both `node` and `npm` are absent.
- Atheris 3.1.0 is installed only on x86_64 because the selected release has no
  supported non-x86_64 Linux wheel.
- Fedora package names differ from Debian examples: for example, AFL++ is
  packaged as `american-fuzzy-lop`, and the installer asks repositories which
  names are actually available.
- CodeQL, Joern, the Ghidra distribution, Google Cloud CLI, Claude Code,
  Copilot CLI, Ollama, frida-server, the Gradle fallback, and angr are
  upstream/manual installs. The host installer prints this boundary.
- The standard RAPTOR Python environment uses `z3-solver==4.15.4.0`. Do not
  install angr into that environment; see [angr isolation](#angr-isolation).


## Optional upstream tools on the Fedora host

These recipes cover large or upstream-only tools that Fedora 44 does not
provide through the host installer. Review each project's licence and release
notes before downloading, and revalidate checksums when changing a pinned
version.

Before using the user-local installs:

```bash
mkdir -p "$HOME/.local/bin" "$HOME/.local/opt"
export PATH="$HOME/.local/bin:$PATH"
cd "$HOME/src/copilot/raptor"
source .venv/bin/activate
```

Python packages added by the recipes below use
`packaging/fedora/constraints-host-tools.txt` so their shared dependencies
remain compatible with the Semgrep installation in RAPTOR's main environment.

### CodeQL 2.26.4 official bundle

Read GitHub's
[CodeQL CLI setup documentation](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli)
and [CodeQL Terms and Conditions](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md)
before downloading. CodeQL is governed by separate terms and use
restrictions; RAPTOR's MIT licence does not cover it.

The pinned official bundle is Linux amd64-only:

```bash
(
set -euo pipefail

sudo dnf install -y curl tar zstd
test "$(uname -m)" = x86_64 || {
  printf '%s\n' 'CodeQL bundle 2.26.4 is available here only for x86_64.' >&2
  exit 1
}

CODEQL_VERSION=2.26.4
CODEQL_URL="https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.zst"
CODEQL_SHA256="a9872c9075f85374a8d03546263c6dc01fde50a29baea9fc08dcc6b25cc2efd5"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fL --retry 5 --retry-all-errors --retry-delay 2 \
  "$CODEQL_URL" -o "$tmp/codeql-bundle.tar.zst"
printf '%s  %s\n' "$CODEQL_SHA256" "$tmp/codeql-bundle.tar.zst" |
  sha256sum -c -

test ! -e "$HOME/.local/opt/codeql" || {
  printf '%s\n' 'Move the existing ~/.local/opt/codeql before installing.' >&2
  exit 1
}
tar --no-same-owner --use-compress-program=unzstd \
  -xf "$tmp/codeql-bundle.tar.zst" \
  -C "$HOME/.local/opt"
ln -sfn "$HOME/.local/opt/codeql/codeql" "$HOME/.local/bin/codeql"
codeql version
test -d "$HOME/.local/opt/codeql/qlpacks"
)
```

### Joern 4.0.622

See the official [Joern installation guide](https://docs.joern.io/installation/)
and [Joern release](https://github.com/joernio/joern/releases/tag/v4.0.622).

```bash
(
set -euo pipefail

sudo dnf install -y curl unzip java-21-openjdk-devel

JOERN_VERSION=4.0.622
case "$(uname -m)" in
  x86_64)
    JOERN_ARCH=x86_64
    JOERN_SHA256=d559b569b6180726c2b5b7a5b9b25753c1cbf42c8143ba11311df0d47b2a40a6
    ;;
  aarch64|arm64)
    JOERN_ARCH=arm64
    JOERN_SHA256=fceac538dfbc11b7833878532428bdd255ba2fc89762c98d99577edc4c780a1a
    ;;
  *)
    printf 'Unsupported Joern architecture: %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac

JOERN_FILE="joern-cli-linux-${JOERN_ARCH}.zip"
JOERN_URL="https://github.com/joernio/joern/releases/download/v${JOERN_VERSION}/${JOERN_FILE}"
JOERN_ROOT="$HOME/.local/opt/joern-$JOERN_VERSION"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fL --retry 5 --retry-all-errors --retry-delay 2 \
  "$JOERN_URL" -o "$tmp/$JOERN_FILE"
printf '%s  %s\n' "$JOERN_SHA256" "$tmp/$JOERN_FILE" | sha256sum -c -
test ! -e "$JOERN_ROOT"
mkdir -p "$JOERN_ROOT"
unzip -q "$tmp/$JOERN_FILE" -d "$JOERN_ROOT"

for tool in \
  joern joern-export joern-flow joern-parse joern-scan joern-slice \
  c2cpg.sh ghidra2cpg javasrc2cpg jimple2cpg kotlin2cpg php2cpg \
  pysrc2cpg rubysrc2cpg; do
  ln -sfn "$JOERN_ROOT/joern-cli/$tool" "$HOME/.local/bin/$tool"
done
python - "$JOERN_ROOT/joern-cli/lib" "$JOERN_VERSION" <<'PY'
from pathlib import Path
import sys

prefix = "io.joern.joern-cli-"
jar, = sorted(Path(sys.argv[1]).glob(f"{prefix}*.jar"))
version = jar.name[len(prefix):-4]
assert version == sys.argv[2], f"unexpected Joern version: {version}"
print(f"Joern {version}")
PY
)
```

### Ghidra 12.1.3, JDK 21, and PyGhidra

Use the official
[Ghidra 12.1.3 release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.3_build).
RAPTOR's validated configuration uses JDK 21 and PyGhidra 3.1.0.

```bash
(
set -euo pipefail

sudo dnf install -y curl unzip java-21-openjdk-devel

GHIDRA_VERSION=12.1.3
GHIDRA_BUILD_DATE=20260817
GHIDRA_FILE="ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD_DATE}.zip"
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_FILE}"
GHIDRA_SHA256=93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54
GHIDRA_ROOT="$HOME/.local/opt/ghidra-$GHIDRA_VERSION"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fL --retry 5 --retry-all-errors --retry-delay 2 \
  "$GHIDRA_URL" -o "$tmp/$GHIDRA_FILE"
printf '%s  %s\n' "$GHIDRA_SHA256" "$tmp/$GHIDRA_FILE" | sha256sum -c -
test ! -e "$GHIDRA_ROOT"
unzip -q "$tmp/$GHIDRA_FILE" -d "$tmp"
mv "$tmp/ghidra_${GHIDRA_VERSION}_PUBLIC" "$GHIDRA_ROOT"

ln -sfn "$GHIDRA_ROOT/ghidraRun" "$HOME/.local/bin/ghidra"
ln -sfn \
  "$GHIDRA_ROOT/support/analyzeHeadless" \
  "$HOME/.local/bin/analyzeHeadless"
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
export GHIDRA_INSTALL_DIR="$GHIDRA_ROOT"
test -x "$JAVA_HOME/bin/java"
python -m pip install \
  -c packaging/fedora/constraints-host-tools.txt \
  "pyghidra==3.1.0"
python -c \
  'from importlib.metadata import version; import pyghidra; print(version("pyghidra"))'
)
```

Set the paths in the shell that launches RAPTOR:

```bash
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
export GHIDRA_INSTALL_DIR="$HOME/.local/opt/ghidra-12.1.3"
```

Persist those two exports in your shell profile if you use the host
installation regularly.

### Google Cloud CLI 583.0.0, bq, and BigQuery clients

The archive includes `gcloud`, `bq`, and `gsutil`. See Google's official
[Google Cloud CLI installation guide](https://cloud.google.com/sdk/docs/install).

```bash
(
set -euo pipefail

sudo dnf install -y curl tar

GCLOUD_VERSION=583.0.0
case "$(uname -m)" in
  x86_64)
    GCLOUD_ARCH=x86_64
    GCLOUD_SHA256=84c5e4798836bda13aa82c3e84fa1acd0c4e4ca5318f7141052e3a5a26a7cc97
    ;;
  aarch64|arm64)
    GCLOUD_ARCH=arm
    GCLOUD_SHA256=8ce6287e01e54b53d2e9618d124b62ac85efe5a093904ae027b17f2057030662
    ;;
  *)
    printf 'Unsupported Google Cloud CLI architecture: %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac

GCLOUD_FILE="google-cloud-cli-${GCLOUD_VERSION}-linux-${GCLOUD_ARCH}.tar.gz"
GCLOUD_URL="https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/${GCLOUD_FILE}"
GCLOUD_ROOT="$HOME/.local/opt/google-cloud-cli-$GCLOUD_VERSION"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fL --retry 5 --retry-all-errors --retry-delay 2 \
  "$GCLOUD_URL" -o "$tmp/$GCLOUD_FILE"
printf '%s  %s\n' "$GCLOUD_SHA256" "$tmp/$GCLOUD_FILE" | sha256sum -c -
test ! -e "$GCLOUD_ROOT"
mkdir -p "$GCLOUD_ROOT"
tar --no-same-owner -xzf "$tmp/$GCLOUD_FILE" -C "$GCLOUD_ROOT"

ln -sfn \
  "$GCLOUD_ROOT/google-cloud-sdk/bin/gcloud" \
  "$HOME/.local/bin/gcloud"
ln -sfn "$GCLOUD_ROOT/google-cloud-sdk/bin/bq" "$HOME/.local/bin/bq"
ln -sfn \
  "$GCLOUD_ROOT/google-cloud-sdk/bin/gsutil" \
  "$HOME/.local/bin/gsutil"
gcloud --version
bq version

cd "$HOME/src/copilot/raptor"
source .venv/bin/activate
python -m pip install \
  -c packaging/fedora/constraints-host-tools.txt \
  "google-auth==2.57.1" \
  "google-cloud-bigquery==3.45.0"
python -m pip check
)
```

For local interactive ADC:

```bash
gcloud auth login
gcloud auth application-default login
gcloud config set project YOUR_BILLING_PROJECT_ID
```

For RAPTOR's service-account workflow, keep the JSON outside the checkout and
export only its path:

```bash
export GOOGLE_APPLICATION_CREDENTIALS="$HOME/.config/gcloud/raptor-reader.json"
test -r "$GOOGLE_APPLICATION_CREDENTIALS"
```

BigQuery authorization and billing are separate from installation:

- Query jobs need a billing-enabled project and may incur charges.
- Prefer `roles/bigquery.jobUser` on the job/billing project, or a custom role
  containing only the required job permissions, plus only the dataset/table
  read permissions needed for non-public data.
- Do not describe `roles/bigquery.user` as read-only. At project scope it is
  broader than job execution and includes dataset-creation capabilities.
- RAPTOR's typed BigQuery wrapper enforces a single read-only statement and a
  bytes-billed cap, but IAM scope and billing remain the operator's
  responsibility.

See Google's
[BigQuery IAM roles](https://cloud.google.com/bigquery/docs/access-control)
and [ADC guidance](https://cloud.google.com/docs/authentication/set-up-adc-local-dev-environment).

### GitHub Copilot CLI 1.0.83

The complete Fedora command is in
[Install and authenticate GitHub Copilot CLI](#5-install-and-authenticate-github-copilot-cli):

```bash
mkdir -p "$HOME/.local"
npm install --global --prefix "$HOME/.local" \
  "@github/copilot@1.0.83"
export PATH="$HOME/.local/bin:$PATH"
copilot --version
copilot login
```

This npm path requires Node.js 22 or later.

### Claude Code through the Fedora RPM repository

Anthropic publishes signed DNF repositories for Fedora and RHEL. The following
uses the `latest` channel and selects the pinned 2.1.263-1 RPM release. See the
official
[Claude Code setup guide](https://code.claude.com/docs/en/setup).

```bash
sudo tee /etc/yum.repos.d/claude-code.repo <<'EOF'
[claude-code]
name=Claude Code
baseurl=https://downloads.claude.ai/claude-code/rpm/latest
enabled=1
gpgcheck=1
gpgkey=https://downloads.claude.ai/keys/claude-code.asc
EOF
```

After repository setup completes, install the pinned RPM. On first install, DNF
downloads the repository signing key and prompts for acceptance. Accept the key
only if the displayed fingerprint exactly matches:

```text
31DD DE24 DDFA B679 F42D 7BD2 BAA9 29FF 1A7E CACE
```

```bash
sudo dnf install claude-code-2.1.263-1
claude --version
```

The repository can eventually advance and prune older packages. If that
version is no longer available, review the current supported release before
installing it. Claude Code requires its own eligible account/subscription or
supported provider configuration; installing the RPM does not authenticate
it.

### Ollama 0.33.3

The host command below installs the checksum-pinned upstream binary only. It
does not install models or GPU drivers. See the official
[Ollama Linux guide](https://docs.ollama.com/linux) and
[v0.33.3 release](https://github.com/ollama/ollama/releases/tag/v0.33.3).

```bash
(
set -euo pipefail

sudo dnf install -y curl tar zstd

OLLAMA_VERSION=0.33.3
case "$(uname -m)" in
  x86_64)
    OLLAMA_ARCH=amd64
    OLLAMA_SHA256=c13cea8f3389db4145f8a6cb88d1747242a48639d7c13e3bda7c1ebdc6eebb2f
    ;;
  aarch64|arm64)
    OLLAMA_ARCH=arm64
    OLLAMA_SHA256=4425a112af999ae6572c1ce211fbabeaca7bab23ed5860972acdfc0cc2358420
    ;;
  *)
    printf 'Unsupported Ollama architecture: %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac

OLLAMA_FILE="ollama-linux-${OLLAMA_ARCH}.tar.zst"
OLLAMA_URL="https://github.com/ollama/ollama/releases/download/v${OLLAMA_VERSION}/${OLLAMA_FILE}"
OLLAMA_ROOT="$HOME/.local/opt/ollama-$OLLAMA_VERSION"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fL --retry 5 --retry-all-errors --retry-delay 2 \
  "$OLLAMA_URL" -o "$tmp/$OLLAMA_FILE"
printf '%s  %s\n' "$OLLAMA_SHA256" "$tmp/$OLLAMA_FILE" | sha256sum -c -
test ! -e "$OLLAMA_ROOT"
mkdir -p "$OLLAMA_ROOT"
tar --no-same-owner --use-compress-program=unzstd \
  -xf "$tmp/$OLLAMA_FILE" \
  -C "$OLLAMA_ROOT"
ln -sfn "$OLLAMA_ROOT/bin/ollama" "$HOME/.local/bin/ollama"
ollama --version
)
```

Keep the service on loopback unless you have designed and authenticated a
network boundary:

```bash
OLLAMA_HOST=127.0.0.1:11434 ollama serve
```

No model is present until you deliberately pull or import one. Model weights
have their own licences and acceptable-use terms; review those before use.

### Frida 17.17.0 client and matching frida-server

The host Python setup provides the client side only. A target needs a matching
frida-server build. See Frida's official
[installation guide](https://frida.re/docs/installation/),
[modes of operation](https://frida.re/docs/modes/), and
[release assets](https://github.com/frida/frida/releases/tag/17.17.0).

Install the validated client and CLI versions in RAPTOR's venv:

```bash
cd "$HOME/src/copilot/raptor"
source .venv/bin/activate
python -m pip install \
  -c packaging/fedora/constraints-host-tools.txt \
  "frida==17.17.0" \
  "frida-tools==14.10.4"
frida --version
```

Download the matching server from the official release. Set `FRIDA_TARGET` to
the asset suffix for the remote system, for example `linux-x86_64` or
`android-arm64`, and set the SSH destination:

```bash
(
set -euo pipefail

sudo dnf install -y gh xz

FRIDA_VERSION=17.17.0
FRIDA_TARGET=linux-x86_64
TARGET_SSH=user@example-target
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

gh release download "$FRIDA_VERSION" \
  --repo frida/frida \
  --pattern "frida-server-${FRIDA_VERSION}-${FRIDA_TARGET}.xz" \
  --dir "$tmp"
unxz "$tmp/frida-server-${FRIDA_VERSION}-${FRIDA_TARGET}.xz"
chmod 0755 "$tmp/frida-server-${FRIDA_VERSION}-${FRIDA_TARGET}"
scp \
  "$tmp/frida-server-${FRIDA_VERSION}-${FRIDA_TARGET}" \
  "$TARGET_SSH:/tmp/frida-server-${FRIDA_VERSION}"
)
```

In one terminal, start the server on the target's loopback interface:

```bash
FRIDA_VERSION=17.17.0
TARGET_SSH=user@example-target
ssh "$TARGET_SSH" \
  "chmod 0755 /tmp/frida-server-${FRIDA_VERSION} && exec /tmp/frida-server-${FRIDA_VERSION} -l 127.0.0.1:27042"
```

In a second terminal, create the SSH tunnel:

```bash
TARGET_SSH=user@example-target
ssh -N -L 27042:127.0.0.1:27042 "$TARGET_SSH"
```

In a third terminal, connect through the local end of the tunnel:

```bash
cd "$HOME/src/copilot/raptor"
source .venv/bin/activate
frida-ps -H 127.0.0.1:27042
```

Keep the client and server at exactly 17.17.0. Do not expose frida-server on an
untrusted network; use localhost plus USB/ADB or authenticated SSH forwarding.
RAPTOR does not install a target server or target credentials.

### Gradle 9.7.1 fallback

Use a target's committed Gradle Wrapper whenever `./gradlew` exists:

```bash
cd /absolute/path/to/target
./gradlew --version
```

A global Gradle can silently choose a version different from the project and
is therefore discouraged. For projects without a wrapper, install the pinned
fallback from the official
[Gradle distribution](https://services.gradle.org/distributions/) and see the
[Gradle installation guide](https://docs.gradle.org/current/userguide/installation.html):

```bash
(
set -euo pipefail

sudo dnf install -y curl unzip

GRADLE_VERSION=9.7.1
GRADLE_URL="https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip"
GRADLE_SHA256=acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fL --retry 5 --retry-all-errors --retry-delay 2 \
  "$GRADLE_URL" -o "$tmp/gradle.zip"
printf '%s  %s\n' "$GRADLE_SHA256" "$tmp/gradle.zip" | sha256sum -c -
test ! -e "$HOME/.local/opt/gradle-$GRADLE_VERSION"
unzip -q "$tmp/gradle.zip" -d "$HOME/.local/opt"
ln -sfn \
  "$HOME/.local/opt/gradle-$GRADLE_VERSION/bin/gradle" \
  "$HOME/.local/bin/gradle"
gradle --version
)
```

### angr isolation

The standard RAPTOR venv uses `z3-solver==4.15.4.0`. angr 9.3.4/claripy needs
`z3-solver==4.13.0.0`, so installing angr into the standard host venv would
replace RAPTOR's normal solver pin. Follow angr's recommendation to use an
[isolated Python environment](https://docs.angr.io/en/latest/getting-started/installing.html):

```bash
(
set -euo pipefail

ANGR_VENV="$HOME/.local/venvs/raptor-angr-9.3.4"
python3 -m venv "$ANGR_VENV"
"$ANGR_VENV/bin/python" -m pip install --upgrade pip setuptools wheel
"$ANGR_VENV/bin/python" -m pip install \
  "angr==9.3.4" \
  "z3-solver==4.13.0.0"
"$ANGR_VENV/bin/python" -m pip check
"$ANGR_VENV/bin/python" -c \
  'import angr, z3; print(angr.__version__, z3.get_version_string())'
)
```

That venv is suitable for standalone angr scripts. Do not add it to RAPTOR's
main interpreter path: doing so would bypass the standard host solver pin and
can make the primary environment inconsistent.
