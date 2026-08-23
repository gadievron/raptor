# References

Research papers that RAPTOR's techniques are based on, adapted from,
or were evaluated against. Inline code comments cite these briefly
(author, venue/year, or arXiv id); this page carries the full record.

## Static analysis and audit

- Fabian Yamaguchi, Nico Golde, Daniel Arp, Konrad Rieck.
  **Modeling and Discovering Vulnerabilities with Code Property Graphs.**
  IEEE Symposium on Security and Privacy (S&P), 2014.
  <https://doi.org/10.1109/SP.2014.44>
  — Basis of the `/audit` condition machinery on the Joern CPG:
  `core/audit/condition_cpg.py`, `condition_adequacy.py`,
  `condition_binding.py`, `condition_smt.py`.

- Ziyang Li, Saikat Dutta, Mayur Naik.
  **IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities.**
  ICLR 2025. arXiv:[2405.17238](https://arxiv.org/abs/2405.17238)
  — LLM-inferred source/sink specs driving whole-repo taint queries:
  `core/iris/`, `core/audit/iris_specs.py`,
  `packages/hypothesis_validation/`,
  `packages/llm_analysis/dataflow_validation.py`.

- Chenyuan Yang, Zijie Zhao, Zichen Xie, Haoyu Li, Lingming Zhang.
  **KNighter: Transforming Static Analysis with LLM-Synthesized Checkers.**
  SOSP 2025. arXiv:[2503.09002](https://arxiv.org/abs/2503.09002)
  — Checker synthesis with FP-driven refinement:
  `packages/checker_synthesis/`.

- Dawson Engler, David Yu Chen, Seth Hallem, Andy Chou, Benjamin Chelf.
  **Bugs as Deviant Behavior: A General Approach to Inferring Errors in
  Systems Code.** SOSP 2001. <https://doi.org/10.1145/502034.502041>
  — Majority-belief inference over call sites:
  `core/audit/callsite_consistency.py`.

- Saul Schleimer, Daniel S. Wilkerson, Alex Aiken.
  **Winnowing: Local Algorithms for Document Fingerprinting.**
  SIGMOD 2003. <https://doi.org/10.1145/872757.872770>
  — K-gram fingerprinting for clone drift detection:
  `core/audit/clone_drift.py`.

- Thomas Lengauer, Robert Endre Tarjan.
  **A Fast Algorithm for Finding Dominators in a Flowgraph.**
  ACM Transactions on Programming Languages and Systems 1(1), 1979.
  <https://doi.org/10.1145/357062.357071>
  — Dominator-tree substrate for sanitizer-cut analysis:
  `core/analysis/dominators.py`.

- Saad Ullah, et al.
  **From CVE Entries to Verifiable Exploits: An Automated Multi-Agent
  Framework for Reproducing CVEs** (CVE-Genie).
  arXiv:[2509.01835](https://arxiv.org/abs/2509.01835)
  — Motivates per-stage model role separation:
  `core/llm/scorecard/stage_roles.py`.

## LLM orchestration

- Noah Shinn, Federico Cassano, Ashwin Gopinath, Karthik Narasimhan,
  Shunyu Yao.
  **Reflexion: Language Agents with Verbal Reinforcement Learning.**
  NeurIPS 2023. arXiv:[2303.11366](https://arxiv.org/abs/2303.11366)
  — The `/validate` → `/audit` verdict feedback loop:
  `core/audit/feedback.py`, `core/llm/scorecard/validate_feedback.py`,
  `core/coverage/journal.py`.

- Xuezhi Wang, et al.
  **Self-Consistency Improves Chain of Thought Reasoning in Language
  Models.** ICLR 2023. arXiv:[2203.11171](https://arxiv.org/abs/2203.11171)
  — Independent-sample agreement in multi-review:
  `core/audit/multi_review.py`.

- Sebastian Farquhar, Jannik Kossen, Lorenz Kuhn, Yarin Gal.
  **Detecting hallucinations in large language models using semantic
  entropy.** Nature 630 (2024).
  <https://doi.org/10.1038/s41586-024-07421-0>
  — Reasoning-divergence proxy for multi-model panels:
  `core/llm/semantic_entropy.py`.

- Caleb Gross.
  **Sift or Get Off the PoC: Applying Information Retrieval to
  Vulnerability Research with SiftRank.**
  arXiv:[2512.06155](https://arxiv.org/abs/2512.06155)
  — Listwise LLM ranking for triage ordering:
  `core/llm/ranking.py`, `packages/llm_analysis/rank_stage.py`.
  Reference implementation (MIT):
  <https://github.com/noperator/siftrank>.

## Prompt-injection defense research

- Milad Nasr, et al.
  **The Attacker Moves Second: Stronger Adaptive Attacks Bypass
  Defenses Against LLM Jailbreaks and Prompt Injections.**
  arXiv:[2510.09023](https://arxiv.org/abs/2510.09023)
  — Adaptive-attack meta-result shaping the defense-in-depth posture:
  `core/security/llm_family.py`, `core/security/prompt_envelope.py`.

- Keegan Hines, et al.
  **Defending Against Indirect Prompt Injection Attacks With
  Spotlighting.** arXiv:[2403.14720](https://arxiv.org/abs/2403.14720)
  — Datamarking (adopted): `core/security/prompt_envelope.py`.

- Sizhe Chen, Julien Piet, Chawin Sitawarin, David Wagner.
  **StruQ: Defending Against Prompt Injection with Structured Queries.**
  arXiv:[2402.06363](https://arxiv.org/abs/2402.06363)
  — Evaluated for RAPTOR; adopted as a model-profile entry
  (model-trained delimiters when available).

- Sizhe Chen, et al.
  **SecAlign: Defending Against Prompt Injection with Preference
  Optimization.** arXiv:[2410.05451](https://arxiv.org/abs/2410.05451)
  (see also Meta SecAlign,
  arXiv:[2507.02735](https://arxiv.org/abs/2507.02735))
  — Evaluated for RAPTOR; adopted as a model-profile entry.

- Tianneng Shi, et al.
  **PromptArmor: Simple yet Effective Prompt Injection Defenses.**
  arXiv:[2507.15219](https://arxiv.org/abs/2507.15219)
  — Evaluated for RAPTOR; skipped (its benchmarks exclude
  adversarial-by-design corpora like scanned hostile repos).

- Egor Zverev, et al.
  **ASIDE: Architectural Separation of Instructions and Data in
  Language Models.** arXiv:[2503.10566](https://arxiv.org/abs/2503.10566)
  — Evaluated for RAPTOR; skipped (requires model forward-pass
  modification).
