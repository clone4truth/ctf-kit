# Research and practice basis

- [Model Context Protocol tools specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools): tool schemas, annotations, errors, and structured content. CTF Kit exposes risk annotations and structured results accordingly.
- [Model Context Protocol schema](https://modelcontextprotocol.io/specification/2025-11-25/schema): `outputSchema`, `structuredContent`, and tool annotation definitions.
- [ReAct: Synergizing Reasoning and Acting in Language Models](https://arxiv.org/abs/2210.03629): motivates interleaving hypotheses, actions, and observations instead of generating a static tool list.
- [Reflexion: Language Agents with Verbal Reinforcement Learning](https://arxiv.org/abs/2303.11366): motivates retaining concise, evidence-backed lessons after an evaluated outcome rather than blindly accumulating transcripts.
- [AgentBench: Evaluating LLMs as Agents](https://arxiv.org/abs/2308.03688): motivates end-to-end task evaluation, bounded trajectories, and measuring outcome rather than tool-call volume.

## Practice method

Use a fixture corpus spanning crypto, web, forensics, stego, rev, and pwn. Each case
must declare the expected category, allowed tools, known flag, and maximum calls. Score:

1. category accuracy;
2. flag precision and recall (false positives count);
3. solve rate;
4. calls and elapsed time to verified flag;
5. unavailable/error rate;
6. reproducibility from the recorded commands and artifact digest.

Keep synthetic smoke runs separate from learning state. Promote a workflow or tool
ranking only after repeated end-to-end successes on non-training fixtures.
