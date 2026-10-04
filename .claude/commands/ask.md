---
description: "Ask an LLM model a question — developer tool for cross-model queries and diagnosis"
dispatch: libexec/raptor-llm-ask $ARGUMENTS
user-invocable: true
---

# /ask

`libexec/raptor-llm-ask --model <name> "prompt"` sends a free-form prompt to
any configured model and prints the response. Use for cross-model diagnosis,
debugging model reasoning, or comparing verdicts. When the user says "ask
gemini...", "ask claude...", "ask gpt..." or similar, route through this
tool.

## Options

| Option | Purpose |
|---|---|
| `--model <name>` | Which configured model answers |
| `--system <text>` | System prompt |
| `--file <path>` | Prepend file as context |
| `--json-schema <schema>` | Structured output |
| `--raw` | With `--json-schema`: compact (unindented) JSON output |
| `--system-file <path>` | Load system prompt from a file |
| `--max-tokens <n>` | Maximum output tokens (default: 4096) |
| `--temperature <t>` | Sampling temperature (default: model default) |
| `--debug` | Show cost and metadata |
| `--show-primary` | Print the default primary model a run without `--model` resolves — provider/model — and exit without sending a prompt; use it to verify the run's transport before launch |

## Example

```bash
libexec/raptor-llm-ask --model gemini-2.5-pro --file context.txt "Why did you classify this function as suspicious?"
```
