# Installing RAPTOR

The single source of truth for what RAPTOR needs. RAPTOR runs **inside Claude
Code** and orchestrates external security tools; it bundles none of them. This
page tells you the minimum to get a `/scan` working and what to add per feature.

> Deep LLM/provider configuration (models.json, Bedrock, model selection) lives
> in [`configuration.md`](configuration.md). This page only covers *what to
> install* and *how to authenticate*.

---

## Must vs optional

**Baseline** (everything below the divider is required to run a basic `/scan`):

| Tool | Needed by | Install |
|------|-----------|---------|
| Python 3.10+ (3.12 is the tested/CI version) | everything | your OS / package manager |
| Python deps (`pip install -r requirements.txt`) | everything | see [Install](#install-pip-as-is) |
| Node.js + Claude Code CLI (`claude`) | the launcher — RAPTOR runs *inside* Claude Code | `npm install -g @anthropic-ai/claude-code` |
| **Semgrep** | `/scan`, `/agentic` (the default static engine) | `pip install semgrep` |
| One configured LLM provider (SDK + credentials) | all LLM analysis (validation, triage, exploit/patch) | `pip install anthropic` (or `openai` / `google-genai`) + [auth](#auth--api-key) |

**Optional — install only when you use the feature:**

| Tool | Needed by | Notes |
|------|-----------|-------|
| AFL++ | `/fuzz` | `apt install afl++` (or `brew install afl++`) |
| CodeQL CLI | `/codeql`, `/scan` deep analysis | **Non-commercial only** — free for security research; review GitHub's CodeQL terms before commercial use |
| rr + gcov + AddressSanitizer | `/crash-analysis` | Linux x86_64 only; needs `--privileged` (see below). gcov ships with gcc; ASan is a compiler flag (`-fsanitize=address`) |
| gdb + binutils (`nm`, `objdump`, `addr2line`, `file`) | binary analysis (`/binary`, `/fuzz` crash triage) | pre-installed on most Linux; `brew install gdb` on macOS |
| Frida | `/frida` (dynamic instrumentation) | `pip install frida frida-tools` |
| BigQuery credentials (`GOOGLE_APPLICATION_CREDENTIALS`) | `/oss-forensics` (GH Archive queries) | Google Cloud project + service-account key |
| Ollama | local / free LLM inference (an alternative provider) | https://ollama.ai — pair with the `openai` SDK (OpenAI-compatible endpoint) |

Smaller optional Python extras (all commented in `requirements.txt`): `tree-sitter` + language grammars (richer inventory metadata), `z3-solver` (SMT constraint analysis), `beautifulsoup4` + `playwright` (`/web` scanning).

---

## Install (pip, as-is)

RAPTOR installs its Python dependencies with **pip** from `requirements.txt` —
there is no packaging step to build.

### Option 1: Manual

```bash
# Clone the repo
git clone https://github.com/gadievron/raptor.git
cd raptor

# Install Python dependencies (the 9 core deps)
pip install -r requirements.txt

# Install Claude Code (the launcher). -g puts `claude` on PATH everywhere.
npm install -g @anthropic-ai/claude-code

# Install Semgrep (required for scanning)
pip install semgrep

# Install one LLM provider SDK (Anthropic shown; openai / google-genai also work)
pip install anthropic

# Launch RAPTOR from the repo root
claude
```

You can also launch through the `bin/raptor` wrapper (add `bin/` to your `PATH`,
or symlink it onto a directory already there). It requires `claude` and
`python3`. Check your setup at any time with `raptor doctor`.

### Option 2: Devcontainer (recommended)

Everything above plus every optional tool is pre-installed. Open the repo in VS
Code with **Dev Containers: Open Folder in Container**, or pull the prebuilt
image:

```bash
docker pull danielcuthbert/raptor:latest
docker run --privileged -it -v "$(pwd):/workspaces/raptor" danielcuthbert/raptor:latest
```

Or build it yourself instead of pulling:

```bash
docker build -f .devcontainer/Dockerfile -t raptor:latest .
docker run --privileged -it -v "$(pwd):/workspaces/raptor" raptor:latest
```

The `--privileged` flag is required for the `rr` deterministic debugger used by
`/crash-analysis`. The image is large (**around 6 GB**). It starts from the
Microsoft Python 3.12 devcontainer and adds Semgrep, CodeQL, AFL++, rr, gdb,
binutils, Node.js + the Claude Code CLI, and Playwright/Chromium.

---

## Auth / API key

RAPTOR runs on top of the Claude Code CLI, so **`claude` itself needs Anthropic
authentication** — either an API key or a Claude subscription (Pro/Max):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

RAPTOR's own analysis workers can use a **different** provider than the Claude
Code session that drives them. The supported providers — each configured with
its own env var / SDK — are:

| Provider | SDK to install | Credential |
|----------|----------------|-----------|
| Anthropic (Claude) | `anthropic` | `ANTHROPIC_API_KEY` |
| OpenAI | `openai` | `OPENAI_API_KEY` |
| Google Gemini | `google-genai` (or `openai` shim) | `GEMINI_API_KEY` |
| Mistral | `openai` (compatible endpoint) | `MISTRAL_API_KEY` |
| Ollama (local) | `openai` (compatible endpoint) | none — set `OLLAMA_HOST` |
| AWS Bedrock | stock `anthropic` SDK (`botocore` only for SigV4 signing) | `AWS_BEARER_TOKEN_BEDROCK` or AWS creds |

At minimum you need **one** provider SDK installed and its credential set. For
model selection, per-provider tuning, and the full `models.json` reference, see
[`configuration.md`](configuration.md).

---

## First run + where output lands

From the repo root, start a session and run a command against a target:

```bash
claude
# then, in the session:
/scan /path/to/code
```

Every analysis run writes to a timestamped directory under **`out/`** (or the
active project's directory if you created one with `/project`). The two files
you'll look at first:

| File | What it is |
|------|-----------|
| `report.md` | Human-readable summary of the run |
| `findings.json` | Machine-readable findings (one record per issue) |

The exact path is printed at the end of the run as `OUTPUT_DIR=<path>`.

---

## See also

- [`configuration.md`](configuration.md) — LLM providers, models.json, tuning
- [`commands.md`](commands.md) — the full command surface
