# Prompt Injection Defenses: State of the Art (2024–2026) for RAPTOR

Scope: techniques **not** in RAPTOR's planned PR-1 set (envelope/nonce, slot discipline, control-char sanitisation, base64 wrapping, output schema validation, capability isolation, system priming, trust-tag propagation). Verdicts target a security-research framework that must **read** untrusted source code, run on heterogeneous backends (Claude / Gemini / OpenAI / Ollama), and dispatch via subprocess (`claude -p`) and SDK calls.

The single most important meta-result of 2025: Anthropic, OpenAI and DeepMind's joint *"The Attacker Moves Second"* (arXiv 2510.09023) ran adaptive attacks against **12 published defences** and bypassed all of them at >90% ASR. Treat every "near-zero ASR" claim below as fragile under adaptive pressure. Defence-in-depth, not point solutions.

---

## 1. Spotlighting (Hines et al., Microsoft, 2024)

**One-liner.** Three transformations to mark untrusted regions: *delimiting* (random delimiter pair), *datamarking* (replace whitespace with a special token interleaved through the body), *encoding* (base64/ROT13).

**Source.** Hines, Lopez, Hall, Zarfati, Zunger, Kiciman. *Defending Against Indirect Prompt Injection Attacks With Spotlighting*. arXiv 2403.14720. https://arxiv.org/abs/2403.14720 — also Microsoft MSRC's 2025 defence post: https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks/

**Empirical strength.** Original paper: ASR drops from ~50% to <2% on GPT-3.5/4 for the encoding variant on a representative IPI set; "negligible" task-utility loss for datamarking and encoding. Has not been re-evaluated under "Attacker Moves Second" adaptive attacks; expect degradation.

**Applicability to RAPTOR.** Delimiting ~= our envelope, so already covered. **Datamarking is the missing piece** — interleave a per-call nonce token through whitespace inside the envelope (e.g., `if^^X9F2^^(buf^^X9F2^^==^^X9F2^^NULL)`). Cheap, model-agnostic, degrades gracefully on Ollama (smaller models still see "weird whitespace = data").

**Verdict.** **Adopt** — fold datamarking into PR-1 alongside the envelope. ~30 LOC, no extra round-trip.

---

## 2. StruQ / SecAlign / Meta SecAlign (Chen et al., Berkeley + Meta, 2024–2025)

**One-liner.** Fine-tune the model so reserved separator tokens cannot appear in the data channel; SecAlign uses DPO to *prefer* the on-task answer over the injected one.

**Source.**
- StruQ: https://arxiv.org/abs/2402.06363, USENIX Security 2025
- SecAlign: https://arxiv.org/abs/2410.05451
- Meta SecAlign 70B: https://arxiv.org/abs/2507.02735
- BAIR blog: https://bair.berkeley.edu/blog/2025/04/11/prompt-injection-defense/

**Empirical strength.** Optimisation-free attacks → ~0% ASR; against GCG-style optimisation attacks SecAlign cuts ASR by >4x vs. StruQ. Meta released a 70B SecAlign Llama with the published delimiter scheme.

**Applicability to RAPTOR.** Vendor-side; we don't fine-tune Claude/Gemini/GPT. **However**, Meta SecAlign 70B is Ollama-pullable and is the only production-grade prompt-injection-hardened open model today. Worth a profile entry: if the user runs SecAlign-Llama, RAPTOR can use the *real* `[MARK_INST]/[MARK_INPT]` delimiters instead of the generic envelope.

**Verdict.** **Consider** — add a `model_profile` entry for SecAlign-Llama that swaps the envelope for the model's native separators. Skip everything else (we can't fine-tune frontier models).

---

## 3. CaMeL — Capabilities for MachinE Learning (Debenedetti et al., DeepMind, 2025)

**One-liner.** Privileged LLM emits a small Python program; a Quarantined LLM reads untrusted data; capabilities flow with values, and the runtime refuses operations that violate policy.

**Source.** *Defeating Prompt Injections by Design*, arXiv 2503.18813. https://arxiv.org/abs/2503.18813. Simon Willison's analysis: https://simonwillison.net/2025/Apr/11/camel/

**Empirical strength.** AgentDojo: 77% task success **with provable security** vs. 84% undefended. The first defence with a formal model rather than a behavioural claim, so it survives "Attacker Moves Second" by construction (against in-scope threats).

**Applicability to RAPTOR.** Conceptually the closest match for our `/agentic` and `/crash-analysis` flows, but a full CaMeL implementation is a multi-month engineering project. The *transferable* idea: **the privileged LLM (orchestrator) should never see raw target source**. RAPTOR's Stage A in `/validate` already approximates this — the orchestrator reads structured findings JSON, not the file. PR-3 (capability isolation) should make this rule explicit: "untrusted-readers never plan tool calls; planners never read raw target content."

**Verdict.** **Consider (architectural).** Don't port CaMeL; *cite* it as the reference architecture in the threat model doc and align PR-3's capability matrix to its split. The Dual-LLM pattern (§9) is the practical form.

---

## 4. Sandwich Defence / Instruction Reiteration

**One-liner.** Re-state the original task *after* the untrusted block to "remind" the model.

**Source.** Folklore from Learn Prompting; benchmarked in https://arxiv.org/abs/2411.00459 (ACL 2025) and https://arxiv.org/abs/2310.12815 (USENIX 2024).

**Empirical strength.** Slightly better than no defence; useless against adaptive attacks. The 2025 *Soft Instruction De-escalation* paper (https://openreview.net/pdf/08fce647d0d1adee512fe244bc1e0937ab50f678.pdf) explicitly notes that "appending safety instructions provides no security." Sandwich does, however, raise the *lower bound* of robustness on small Ollama models that don't reliably follow system prompts.

**Applicability to RAPTOR.** Cheap insurance for the local-model path. Add an optional post-envelope re-statement of the task, gated by `model_profile.requires_reiteration` (true for Ollama 7B-class models, false for frontier).

**Verdict.** **Consider** for the per-model profile registry. PR-1 can ship without it; add when populating Ollama profiles.

---

## 5. Self-Reflection / Second-Pass Critique

**One-liner.** Ask the model (or a second model) to verify its output didn't follow injected instructions.

**Source.**
- *Safeguarding by Progressive Self-Reflection*, ACL Findings 2025: https://aclanthology.org/2025.findings-emnlp.503.pdf
- *Defense Against Prompt Injection by Leveraging Attack Techniques*, arXiv 2411.00459

**Empirical strength.** Self-reflection improves refusal on harmful generation but is the *primary target* of "Attacker Moves Second" adaptive attacks — a single-shot prompt that survives the producer often survives the critic too. Two-model variants (different families) are stronger but double cost.

**Applicability to RAPTOR.** Already partially have this: `/validate` Stage E is a checker pass on Stage D output. The lever is to **make the checker model different from the producer model** (e.g., producer Claude → checker Gemini) and to feed the checker only the *output JSON*, not the original prompt. That changes the attack surface: an injection that hijacks Claude's output schema must independently survive Gemini's parser.

**Verdict.** **Adopt (cheap form).** Document a "cross-family checker" recommendation in PR-2 output validation. No new code; just an option to dispatch the validator to a different provider.

---

## 6. Token-Level Provenance / Taint Propagation

**One-liner.** Every token carries a trust tag; the runtime refuses to let untrusted tokens influence privileged operations.

**Source.**
- *TaintP2X* (ICSE 2026): https://conf.researchr.org/details/icse-2026/icse-2026-research-track/157/
- Compiler-stage APM/TLV proposal: https://papers.ssrn.com/sol3/papers.cfm?abstract_id=5460154
- ASIDE (§7) is the closest *inside-the-model* implementation.

**Empirical strength.** Mostly proposals. TaintP2X is a static-analysis tool *for finding* taint-style issues in LLM apps, not a runtime defence. The unmodified Anthropic/OpenAI/Gemini APIs do not expose per-token trust labels — there's nowhere to attach the tag.

**Applicability to RAPTOR.** Out of reach at the model level. **At the orchestration level, RAPTOR already does this** via the `untrusted_blocks` parameter and trust-tag propagation across agent hops. Document it as "coarse-grained taint tracking at the prompt-construction boundary" and stop there.

**Verdict.** **Skip** the model-level form; we already have the orchestration-level form under a different name.

---

## 7. ASIDE — Architectural Separation of Instructions and Data (Zverev et al., 2025)

**One-liner.** A 90° rotation on data-token embeddings creates an architectural channel separation; the model literally cannot confuse the two.

**Source.** arXiv 2503.10566. https://arxiv.org/abs/2503.10566

**Empirical strength.** Stronger instruction-data separation than fine-tuning baselines on Llama 3.1, Qwen 2.5, Mistral, *with no extra parameters*. Survives many indirect injection benchmarks without any safety tuning. Untested in the "Attacker Moves Second" round.

**Applicability to RAPTOR.** Requires forward-pass modification of the model. Not deployable for Claude/Gemini/GPT. *Could* be deployed for Ollama if we shipped a patched runtime, which we won't.

**Verdict.** **Skip** (out of scope). Track the upstream — if Ollama or vLLM merges ASIDE, revisit.

---

## 8. PromptArmor (Shi et al., ICLR 2026)

**One-liner.** Send untrusted content to a *separate* off-the-shelf LLM call ("is there an injection in this text? remove it") before the main agent processes it.

**Source.** arXiv 2507.15219. https://arxiv.org/abs/2507.15219

**Empirical strength.** With GPT-4o/4.1/o4-mini: <1% FPR/FNR on AgentDojo, <5% on Open Prompt Injection and TensorTrust. Survives adaptive attacks targeting it specifically. Best-in-class detection result of 2025.

**Applicability to RAPTOR.** **This is the technique you ruled out** ("classifier approaches → false positives on security-research corpora"). Worth re-examining: PromptArmor is not a classifier, it's an LLM doing the classification, and on AgentDojo's task suite (which includes *actual code* and tool outputs) its FPR is sub-1%. **However**, AgentDojo doesn't contain "files literally named `exploit.c` whose comments include `// ignore previous instructions and ...`" — which is exactly what RAPTOR test corpora look like. The FPR claim does not transfer. The 2026 reconsideration question is real but the answer is still no for RAPTOR.

**Verdict.** **Skip (corpus mismatch).** Document the reasoning in the threat model so it's revisitable: "PromptArmor benchmarks exclude adversarial-by-design corpora; revisit if a vulnerability-focused FPR study appears."

---

## 9. Design Patterns: Dual-LLM, Plan-Then-Execute, Action-Selector (Beurer-Kellner et al., 2025)

**One-liner.** Six design patterns that *structurally* prevent prompt injection by separating planning from data exposure.

**Source.** *Design Patterns for Securing LLM Agents Against Prompt Injections*, arXiv 2506.08837. https://arxiv.org/abs/2506.08837. Code samples: https://github.com/ReversecLabs/design-patterns-for-securing-llm-agents-code-samples. Origin of Dual-LLM: Simon Willison, https://simonwillison.net/2023/Apr/25/dual-llm-pattern/

**Empirical strength.** Reference architecture, not a benchmark. The *guarantees* are formal: a planner that never sees untrusted bytes cannot be hijacked into changing the plan. Adopted by Anthropic and Google in their internal agents.

**Applicability to RAPTOR.** Direct fit. Map RAPTOR's existing structure to these patterns:
- `/scan` → **Action-Selector** (planner picks tools; data flows in but instructions don't flow out as new actions)
- `/validate` Stage A → **Plan-Then-Execute** (Stage A plans the checks; later stages execute against untrusted data)
- `/agentic` → **Dual-LLM** is the target shape; orchestrator (privileged) reads only structured outputs, scanners (quarantined) read source

**Verdict.** **Adopt (architectural framing).** Don't add code; *adopt the vocabulary* in PR-3's capability-matrix doc. This is the language Anthropic and Google use; aligning with it makes RAPTOR's architecture legible.

---

## 10. Agents Rule of Two (Meta, 2025)

**One-liner.** An agent session may have **at most two** of: (A) processes untrusted input, (B) accesses sensitive data/tools, (C) changes state or communicates externally. Three → human approval required.

**Source.** Meta AI blog, Oct 2025: https://ai.meta.com/blog/practical-ai-agent-security/. Inspired by Willison's "lethal trifecta."

**Empirical strength.** Policy framework, not an evaluation. Adopted by Meta internally. A rule-of-thumb, not a guarantee — they explicitly say "not a finish line."

**Applicability to RAPTOR.** Excellent fit for `/agentic`, `/crash-analysis`, `/oss-forensics`. Audit each agent against (A/B/C):
- `/scan` workers: A=yes, B=no, C=no → safe
- `/validate` exploit-PoC generation: A=yes, B=yes (writes files), C=yes (runs code) → **trifecta**, must require human approval (currently does, via the "ASK FIRST" policy in CLAUDE.md)
- `/oss-forensics`: A=yes, B=yes (gh API), C=no → 2/3, OK

**Verdict.** **Adopt (audit tool).** Add a Rule-of-Two column to the PR-3 capability matrix. Free; just a checklist.

---

## 11. Vendor Guidance (this is the section you asked about explicitly)

### Anthropic

- **Prompt-injection defences** announcement (Nov 2025): https://www.anthropic.com/news/prompt-injection-defenses — Claude Opus 4.5 cuts ASR to 1.4%; in-the-loop attack-detection classifiers run on tool outputs and computer-use screenshots.
- **Mitigate jailbreaks and prompt injections** (Claude API docs): https://platform.claude.com/docs/en/test-and-evaluate/strengthen-guardrails/mitigate-jailbreaks
- **Use XML tags to structure your prompts**: https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/use-xml-tags — Anthropic explicitly recommends XML tags for separating data from instructions and notes Claude was trained on `<document>/<document_content>/<source>` patterns.
- **Constitutional Classifiers / CC++**: https://www.anthropic.com/research/constitutional-classifiers and https://www.anthropic.com/research/next-generation-constitutional-classifiers — first gen cut jailbreak ASR 86%→4.4% at +23.7% compute; CC++ achieves the same at 40x cost reduction.

**RAPTOR alignment.** Our `<untrusted-${nonce}>` envelope is **explicitly endorsed** by Anthropic's XML-tag guidance. Adopt the `<document>` *outer* wrapping for content from named files (so Claude sees a familiar pattern):
```
<document index="1">
  <source>target/src/foo.c</source>
  <document_content>
    <untrusted-${nonce}>...</untrusted-${nonce}>
  </document_content>
</document>
```

### OpenAI

- **Instruction Hierarchy paper** (April 2024): https://arxiv.org/abs/2404.13208 — system > developer > user > tool, baked into GPT-4o-mini and later. Up to 63% robustness gain on held-out attacks.
- **Safety in building agents**: https://platform.openai.com/docs/guides/agent-builder-safety — "untrusted inputs should be passed through user messages to limit their influence" and "define structured outputs between nodes (enums, fixed schemas) to eliminate freeform channels."
- **Model Spec** (2025/12/18): https://model-spec.openai.com/2025-12-18.html — *"Use untrusted_text blocks when available, or otherwise YAML/JSON/XML format."*
- **Understanding prompt injections** (frontier-security blog post): https://openai.com/index/prompt-injections/

**RAPTOR alignment.** Two concrete asks from OpenAI's docs we don't currently honour:
1. Send untrusted content via the **user role**, never the system or developer role. Audit `cc_dispatch.py` and `llm/client.py`.
2. Use an `<untrusted_text>` tag name (the literal string OpenAI's models are trained to recognise) when targeting GPT models.

### Google / Gemini

- **Lessons from Defending Gemini** (May 2025): https://arxiv.org/abs/2505.14534 and https://storage.googleapis.com/deepmind-media/Security%20and%20Privacy/Gemini_Security_Paper.pdf
- **Layered defence strategy** (Google Security Blog, June 2025): https://security.googleblog.com/2025/06/mitigating-prompt-injection-attacks.html
- **Workspace-side measures**: https://knowledge.workspace.google.com/admin/security/indirect-prompt-injections-and-googles-layered-defense-strategy-for-gemini

Google's strategy has four layers we should mirror conceptually:
1. **Prompt-injection content classifiers** (we skip — corpus mismatch)
2. **Security thought reinforcement** (≈ sandwich/reiteration; document as model-profile option)
3. **Model hardening** via ART-generated training data (vendor-side, not us)
4. **Markdown sanitisation** — strip active markdown elements (links, scripts) before they hit the model

**RAPTOR alignment.** Item 4 is a real gap: scanner output and GitHub content can contain markdown. Add markdown-sanitisation (specifically: strip image/link auto-fetch syntax, HTML, embedded data URIs) to the envelope writer. This is also defence against the *exfiltration* side of injection (model emits `![](attacker.com?leak=...)`).

### Llama / Meta

- **Prompt Guard 2** (classifier model): https://www.llama.com/docs/model-cards-and-prompt-formats/prompt-guard/
- **Llama Guard 3**: https://www.llama.com/docs/model-cards-and-prompt-formats/llama-guard-3/
- **Meta SecAlign 70B** (§2)

**RAPTOR alignment.** When the user runs Ollama with a SecAlign or Prompt-Guard-fronted model, our envelope should defer to the model's native delimiters. Per-model profile.

---

## 12. Other Techniques (briefer)

| Technique | One-liner | Source | Verdict |
|---|---|---|---|
| **Jatmo** (ESORICS 2024) | Task-specific fine-tune that has no instruction-following channel at all | https://arxiv.org/abs/2312.17673 | **Skip** — RAPTOR needs general instruction-following |
| **TensorTrust** | 126K human attacks / 46K defences as a dataset | https://tensortrust.ai/paper/ | **Adopt as eval data** — useful for testing PR-1 |
| **AgentDojo** | 97 tasks × 629 attack cases benchmark | https://arxiv.org/abs/2406.13352 | **Adopt as eval** — closest to RAPTOR's agentic shape |
| **DefensiveTokens** (ICML 2025) | 5 learned soft tokens prepended at runtime; comparable to full fine-tune | https://arxiv.org/abs/2507.07974 | **Skip** — requires model-side training; same path as ASIDE/SecAlign |
| **PromptGuard / Vigil / Rebuff** | Off-the-shelf classifier services | https://github.com/protectai/rebuff, https://github.com/deadbits/vigil-llm | **Skip** — corpus mismatch (same as PromptArmor) |
| **Kill-Chain Canaries** (2026) | Stage-level canary tracking through multi-agent pipelines | https://arxiv.org/abs/2603.28013 | **Consider for forensics** — useful for `/agentic` post-mortem detection, not prevention |
| **WithSecure Llama3-8B-prompt-injection** | Off-the-shelf hardened Ollama model | https://ollama.com/withsecure/llama3-8b-prompt-injection | **Document in profile** — recommend in Ollama setup |
| **IntentGuard** (2025) | Extract intended instructions, search for them in untrusted input, mask conflicts | https://arxiv.org/abs/2512.00966 | **Skip** — adds two LLM calls per dispatch |
| **Tool-Input/Output Firewalls** | Lightweight sanitiser at agent-tool boundary | https://arxiv.org/abs/2510.05244 | **Consider** for `/agentic` MCP-style tool boundaries (post PR-3) |

---

## 13. What we already cover under different names

| Their name | Our name |
|---|---|
| Spotlighting *delimiting* | Envelope tags with nonce (PR-1) |
| Spotlighting *encoding* | Base64 wrapping, per-model gated (PR-1 layer) |
| StruQ separator filtering | Control-char sanitisation + nonce uniqueness (PR-1) |
| Coarse taint propagation | Trust-tag propagation across agent hops (PR-1) |
| Dual-LLM / Action-Selector | Capability isolation (PR-3) |
| Output-channel narrowing (OpenAI) | Output schema validation (PR-2) |
| Slot/named-parameters discipline | Slot discipline (PR-1) |

Add to the PR-1 design doc:
- **Datamarking** (Spotlighting variant) — interleave nonce token through whitespace inside envelopes
- **Anthropic `<document>/<source>` outer wrap** — improves Claude's pattern recognition
- **OpenAI `<untrusted_text>` tag name** — model-profile-gated for GPT targets
- **OpenAI user-role rule** — untrusted bytes never go in system/developer role
- **Markdown sanitisation** (Google's layer 4) — strip auto-fetch markdown / HTML / data URIs before they reach the model
- **Cross-family checker** (PR-2) — let the validator dispatch to a different provider than the producer
- **Rule-of-Two audit column** (PR-3) — annotate each agent with A/B/C; trifecta requires human-in-the-loop

---

## 14. Top 3 for PR-1 / PR-2

### 1. Spotlighting datamarking + Anthropic `<document>/<source>` outer wrap (PR-1)

**Why.** Datamarking is the cheapest effective addition we don't yet have; <30 LOC; preserves task utility on every model tested in the original paper; degrades gracefully on Ollama (small models still pattern-match "this whitespace is weird → data"). The outer `<document>` wrap aligns with Claude's training data and is an explicit Anthropic recommendation. Together: better separation signal, no new dependencies, no extra LLM calls.

### 2. Per-model envelope profiles, including OpenAI `<untrusted_text>` and SecAlign delimiters (PR-1)

**Why.** A profile registry already lives in the PR-1 plan as a stub. Populating it with the *model-trained* delimiters (OpenAI's `<untrusted_text>`, SecAlign's `[MARK_INPT]`, Llama Prompt Guard format) is small, mechanical, and exploits each vendor's own training. This is also what makes the framework "degrade gracefully" on Ollama — the profile picks the right strategy by model name rather than relying on a single envelope working everywhere.

### 3. Cross-family checker for PR-2 output validation

**Why.** The biggest "Attacker Moves Second" lesson: a single-model check is brittle. PR-2 already includes reject-and-retry on schema failure; making the *checker* run on a different provider (producer Claude → checker Gemini, or vice-versa) raises the attack bar from "bypass one model's parser" to "bypass two unrelated parsers simultaneously." Zero new code in the dispatch layer — just a config option to route validation to a different backend. Aligned with OpenAI's own "structured outputs between nodes" guidance and Google's layered-defence philosophy.

PR-3 candidates (not in top 3 but called out): Rule-of-Two audit column on the capability matrix, Dual-LLM / Action-Selector vocabulary in the design doc, markdown sanitisation in the envelope writer.

---

## Sources (consolidated)

- Hines et al., *Spotlighting*, arXiv 2403.14720 — https://arxiv.org/abs/2403.14720
- Microsoft MSRC, *How Microsoft defends against IPI* (2025) — https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks/
- Chen et al., *StruQ*, USENIX Sec 2025 — https://arxiv.org/abs/2402.06363
- Chen et al., *SecAlign* — https://arxiv.org/abs/2410.05451
- Meta, *SecAlign 70B* — https://arxiv.org/abs/2507.02735
- BAIR blog, StruQ/SecAlign — https://bair.berkeley.edu/blog/2025/04/11/prompt-injection-defense/
- Debenedetti et al., *CaMeL* — https://arxiv.org/abs/2503.18813
- Willison on CaMeL — https://simonwillison.net/2025/Apr/11/camel/
- Wallace et al., *Instruction Hierarchy* — https://arxiv.org/abs/2404.13208
- OpenAI, *Understanding prompt injections* — https://openai.com/index/prompt-injections/
- OpenAI, *Safety in building agents* — https://platform.openai.com/docs/guides/agent-builder-safety
- OpenAI, *Model Spec 2025/12/18* — https://model-spec.openai.com/2025-12-18.html
- Anthropic, *Mitigating prompt injection (browser use)* — https://www.anthropic.com/news/prompt-injection-defenses
- Anthropic, *Mitigate jailbreaks* — https://platform.claude.com/docs/en/test-and-evaluate/strengthen-guardrails/mitigate-jailbreaks
- Anthropic, *Use XML tags* — https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/use-xml-tags
- Anthropic, *Constitutional Classifiers* — https://www.anthropic.com/research/constitutional-classifiers
- Anthropic, *Constitutional Classifiers++* — https://www.anthropic.com/research/next-generation-constitutional-classifiers
- DeepMind, *Lessons from Defending Gemini* — https://arxiv.org/abs/2505.14534
- Google Security Blog, *Layered defence* — https://security.googleblog.com/2025/06/mitigating-prompt-injection-attacks.html
- Beurer-Kellner et al., *Design Patterns for Securing LLM Agents* — https://arxiv.org/abs/2506.08837
- Willison, *Dual LLM Pattern* (2023, foundational) — https://simonwillison.net/2023/Apr/25/dual-llm-pattern/
- Wu et al., *IsolateGPT (SecGPT)*, NDSS 2025 — https://arxiv.org/abs/2403.04960
- Zverev et al., *ASIDE* — https://arxiv.org/abs/2503.10566
- Shi et al., *PromptArmor*, ICLR 2026 — https://arxiv.org/abs/2507.15219
- Chen et al., *DefensiveTokens*, ICML 2025 — https://arxiv.org/abs/2507.07974
- Meta AI, *Agents Rule of Two* — https://ai.meta.com/blog/practical-ai-agent-security/
- *The Attacker Moves Second* (OpenAI/Anthropic/DeepMind) — https://arxiv.org/abs/2510.09023
- Willison commentary on both papers — https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/
- AgentDojo benchmark — https://arxiv.org/abs/2406.13352, https://agentdojo.spylab.ai/
- Tensor Trust dataset — https://tensortrust.ai/paper/
- Jatmo, ESORICS 2024 — https://arxiv.org/abs/2312.17673
- Llama Prompt Guard 2 — https://www.llama.com/docs/model-cards-and-prompt-formats/prompt-guard/
- WithSecure Llama3-8B (Ollama) — https://labs.withsecure.com/publications/llama3-prompt-injection-hardening
- OWASP LLM01:2025 — https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- tldrsec curated list — https://github.com/tldrsec/prompt-injection-defenses
