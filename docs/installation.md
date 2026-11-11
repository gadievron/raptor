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

<!-- raptor:release-tag v3.1.0 -->

These instructions use the stable RAPTOR release, `v3.1.0`. Contributors
working on unreleased code should use the [developer setup](developers.md#working-on-the-development-version).

## Option 1: Install manually

```bash
# Clone the stable release
git clone --branch v3.1.0 https://github.com/gadievron/raptor.git
cd raptor

# Install the checkout's Python dependencies with uv
if [ -f uv.lock ]; then
  uv sync --locked
else
  uv venv
  uv pip install -r requirements.txt
fi
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

Start with the stable release checkout. If you already have a checkout, switch
to `v3.1.0` before using it with the container:

```bash
git clone --branch v3.1.0 https://github.com/gadievron/raptor.git
cd raptor
```

Using containers is a common security practice to restrict agents from accessing areas
of your filesystem you don't want them to, as well as limiting the blast radius of any
malicious code that may execute (e.g via supply-chain attack). The image is large. It
starts from the Microsoft Python 3.14 devcontainer and adds static analysis, fuzzing,
and browser automation tooling.

The published image contains tools and dependencies, not the RAPTOR framework.
Mounting the release checkout selects the RAPTOR version; the image digest pins
the tools environment separately. The `latest` image tag refers to that tools
environment, not to a RAPTOR release. You can pull it with:
```bash
docker pull docker.io/danielcuthbert/raptor:latest@sha256:4abff7ceb4a251cea752d36395d0c26ded89984cf29801ca611e2ce271e8b846
```

or build it locally using the included `Dockerfile`:
```bash
docker build -f .devcontainer/Dockerfile -t raptor:local .
```

The Linux image omits Windows-only packaging launchers, including copies inside
bundled Python wheels. The packaging tools remain installed. WSL uses their
Linux launchers; native Windows installations keep their own Windows launchers.
The cleanup runs during the Linux image build.

To build a redistributable image on Linux, use Buildah's
full-layer squashing so removed files from the base image are excluded too:

```bash
sudo buildah build --format docker --squash -f .devcontainer/Dockerfile -t localhost/raptor:local .
sudo buildah push localhost/raptor:local docker-daemon:raptor:local
```

This requires Buildah and a running Docker daemon. Publication also uses
full-layer squashing. An ordinary Docker build retains the inherited base layers, including
bytes deleted from the final filesystem. Squashed-image updates download the
new combined layer rather than reusing individual base layers. Windows helpers
may reappear if you reinstall packaging tools inside a running container.

The image expects the RAPTOR framework (this repo) to be mounted into
`/workspaces/raptor` on startup. You can optionally mount a target folder for local
analysis.

To start the published image:
```bash
docker run -it \
  -v "$(pwd):/workspaces/raptor" \
  docker.io/danielcuthbert/raptor:latest@sha256:4abff7ceb4a251cea752d36395d0c26ded89984cf29801ca611e2ce271e8b846
```

To mount a target folder as well:
```bash
docker run -it \
  -v "$(pwd):/workspaces/raptor" \
  -v "/path/to/target-folder:/workspaces/target" \
  docker.io/danielcuthbert/raptor:latest@sha256:4abff7ceb4a251cea752d36395d0c26ded89984cf29801ca611e2ce271e8b846
```

For a locally built image, replace the published image reference in these commands
with `raptor:local`.

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

### Browser automation runtime

The Linux container runs Playwright with its installed system Node.js, selected
through `PLAYWRIGHT_NODEJS_PATH=/usr/bin/node`. This avoids shipping a second
Node runtime. Keep that environment variable when launching browser automation
inside the container. Manual installations continue to use Playwright's default
runtime unless you configure your own.

If you reinstall or upgrade Playwright inside a running container, its wheel can
restore the bundled Node executable. Rebuild the image to apply the cleanup and
validate the updated driver against system Node.

The Linux container uses Debian's unbranded Chromium for web scanning, selected
by `RAPTOR_WEB_BROWSER_EXECUTABLE=/usr/bin/chromium`. It does not download or ship
Google Chrome for Testing. The browser's complete package copyright inventory is
available at `/usr/share/doc/chromium/copyright`; the main project license does
not replace the terms of its third-party components.

Browser updates come through Debian packages when the image is rebuilt. Before
publication, an offline check exercises the installed browser with the installed
Playwright version. Manual installations keep Playwright's default browser unless
you set `RAPTOR_WEB_BROWSER_EXECUTABLE` to a different trusted Chromium executable.


## Session names in Claude Code

RAPTOR names launcher-owned sessions `raptor · <project> · <target basename>`.
Projectless sessions use `raptor · projectless · <target basename>` when a
launcher target or a witnessed run from that session supplies it. A session
without an authenticated RAPTOR binding is left alone. Names use the session's own project binding, never
another terminal's active-project bookmark. Target labels come from that project's
current target, or the projectless session's own run/launcher context, never
shell-command text or another terminal's runs. Run targets are display metadata
only and never authorize work or establish project membership.

The title hook runs on start, resume and fork, and before user turns. Loading a
project or changing its target refreshes the name at the next supported hook
boundary. Claude's documented `sessionTitle` hook output applies the change;
RAPTOR does not edit transcript files, simulate keystrokes or start a model call.
See the [Claude hook reference](https://code.claude.com/docs/en/hooks).

A manual `/rename` or explicit frontend title takes precedence. Once the hook
observes a custom title that RAPTOR did not request or confirm, automatic naming
stops for that conversation. Forks preserve an inherited custom title. Clients
that omit current-title feedback are not renamed during user turns.

Naming is optional. Hook errors, timeouts, unavailable storage and contended locks
never prevent launch or a user turn. A requested title is not marked confirmed
until Claude reports it back; retries are bounded to three per desired title.
Concurrent conversations use distinct frontend session IDs and separate locks.
Bookkeeping lives in `sessions.d/.titles` under the operator registry and honors
`RAPTOR_REGISTRY_HOME`. No project settings, run identities or session credentials
are changed by naming.
