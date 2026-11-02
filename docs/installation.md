# Installation

[Documentation index](README.md)

Choose the manual checkout or container route below. Both launch the same interactive
RAPTOR session. For standalone command-line use without Claude Code, see the [Python CLI
guide](python-cli.md#running-fully-standalone-no-claude-code).

**Related documentation:**
[Dependencies](dependencies.md) |
[Installation protection](installation-protection.md) |
[Python CLI](python-cli.md) |
[Troubleshooting](troubleshooting.md)

**On this page:**

- [Prerequisites](#prerequisites)
- [Option 1: Install manually](#option-1-install-manually)
- [Option 2: Run in a container (recommended)](#option-2-run-in-a-container-recommended)

## Prerequisites

- **Claude Code** with an active subscription (Max, Pro, Team, or Enterprise) or an
  Anthropic API key. This is the orchestration layer for the interactive `raptor` shell
  -- optional if you only need the standalone CLIs, see [standalone CLI
  setup](python-cli.md#running-fully-standalone-no-claude-code).
- **[uv](https://docs.astral.sh/uv/)** for Python dependency management, **Python
  3.12+**, and **Node.js 18+**.
- **Semgrep** (`uv tool install semgrep`) for source scanning. Standalone SCA does not
  require it. CodeQL is optional but recommended.

For the analysis dispatch layer (the LLM that analyses individual findings), Claude Code
itself handles everything by default -- no extra API keys needed. If you want
multi-model analysis (e.g. Claude + GPT + Gemini) or a fully local setup, you will need
to configure the other provider(s). See [LLM providers](llm.md).

## Option 1: Install manually

```bash
# Clone the repo
git clone https://github.com/gadievron/raptor.git
cd raptor

# Install Python dependencies
uv sync --locked
source .venv/bin/activate

# Install Claude Code (if you don't already have it)
npm install -g @anthropic-ai/claude-code

# Install Semgrep (required for scanning)
uv tool install semgrep

# Add the launcher to your PATH -- put this in your shell profile to make it
# permanent. Append rather than prepend, so system directories stay ahead of
# the repo. (Alternatively, symlink bin/raptor into a directory already on PATH.)
export PATH="$PATH:$PWD/bin"

# Launch RAPTOR
raptor
```

The `raptor` launcher is the recommended way to start a session, and it works from any
directory -- it resolves the RAPTOR installation, remembers the directory you launched
from (so commands like `/scan` default to it), runs the pre-flight trust and project
checks, loads the coverage-tracking plugin, and sanitises the environment before handing
off to Claude Code. It also takes an optional target path and flags like `--project`,
`--continue`, and `--model` -- see `raptor --help`.

Running plain `claude` from inside the repo directory also works -- Claude Code picks up
RAPTOR's configuration from the checkout -- but you skip everything the launcher does
above: no pre-flight checks, no coverage tracking, and commands that default to "the
directory you ran this from" can't see it.

Experimental Linux installation protection is available with `--protect-install`;
ordinary launches are unchanged. Existing Claude configuration and ordinary user files
retain their normal permissions. See [installation
protection](installation-protection.md) for setup, writable locations, and platform
requirements.

**Important:** RAPTOR loads its configuration from the repo directory. If you run
`claude` from any other directory, you get plain Claude Code, not RAPTOR. The `raptor`
launcher avoids this failure mode entirely.

## Option 2: Run in a container (recommended)

Start with a checkout if you do not already have one:

```bash
git clone https://github.com/gadievron/raptor.git
cd raptor
```

Using containers is a common security practice to restrict agents from accessing areas
of your filesystem you don't want them to, as well as limiting the blast radius of any
malicious code that may execute (e.g via supply-chain attack). The image is large. It
starts from the Microsoft Python 3.14 devcontainer and adds static analysis, fuzzing,
and browser automation tooling.

You can pull down a pre-built image:
```bash
docker pull danielcuthbert/raptor:latest
```

or build it locally using the included `Dockerfile`:
```bash
docker build -f .devcontainer/Dockerfile -t danielcuthbert/raptor:latest .
```

The image expects the RAPTOR framework (this repo) to be mounted into
`/workspaces/raptor` on startup. You can optionally mount a target folder for local
analysis.

To start the container:
```bash
docker run -it \
  -v "$(pwd):/workspaces/raptor" \
  danielcuthbert/raptor:latest
```

To mount a target folder as well:
```bash
docker run -it \
  -v "$(pwd):/workspaces/raptor" \
  -v "/path/to/target-folder:/workspaces/target" \
  danielcuthbert/raptor:latest
```

Add `--privileged` if you need the `rr` deterministic debugger.

VS Code devcontainers are also supported. To mount a target folder, add it to the
`mounts` section of `.devcontainer/devcontainer.json`:
```jsonc
"mounts": [
  // ...existing entries...
  "source=/path/to/target-folder,target=/workspaces/target,type=bind,consistency=cached"
]
```

Then open the repo in VS Code — it will prompt you to reopen in the container:
```bash
cd /path/to/raptor
code .
```

The container installs the pinned CodeQL bundle on first use. To install it ahead of
time, run `codeql --raptor-install`; set `RAPTOR_CODEQL_AUTO_INSTALL=0` to require
explicit installation. See [CodeQL setup](codeql.md) for cache locations and offline
provisioning.

Either way, once you're inside the container, run `raptor` to get started.


For optional Python dependency groups, see [Python
packages](dependencies.md#python-packages). After setup, return to [your first
run](../README.md#what-to-expect-on-a-first-run).
