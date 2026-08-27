# AI Fundamentals — A Crash Course

A condensed curriculum for engineers who want a working understanding of modern AI systems without spending weeks on it. Total time: ~4 hours, broken into 10 focused modules.

The goal isn't to make you an AI researcher. It's to give you the durable mental models that explain every tool, framework, and trend you'll encounter — so you stop chasing tools and start seeing patterns.

---

## How to use this guide

- Each module is ~20–30 minutes of focused reading/discussion.
- Modules build on each other; do them in order the first time through.
- Each module ends with a "what you should be able to say" checklist — use it to verify understanding before moving on.
- Come back to this doc as a reference. The mental models compound over time.

---

## Two frames that run through the whole course

These aren't modules but lenses to keep in mind throughout:

**The Bitter Lesson** — General methods plus scale beat clever, hand-engineered approaches. Every time researchers tried to bake human knowledge into AI systems, simpler approaches with more compute eventually won. When you make architectural bets, bet on what scales — not what's clever.

**The Compositionality Principle** — Modern AI engineering is about composing simple components (prompts, tools, retrievers, skills, agents, evals) cleanly. The architectural mindset matters more than prompt cleverness. Most production AI systems are 80% plumbing, 20% model.

---

## Course Outline

### Module 1: How LLMs Actually Work
**Time: ~20 min**

The foundational mental model. Without this, the rest of the course is just terminology.

**Key concepts:**
- LLMs as next-token predictors (not reasoners)
- Tokens vs words, and why this matters
- The context window as the master constraint
- The training pipeline: pretraining → SFT → RLHF
- Why hallucinations happen (and why they can't be fully eliminated)
- What LLMs are good at vs bad at
- The Bitter Lesson — why scale beats cleverness

**You'll be able to say:**
- "An LLM is a next-token predictor; everything else is emergent."
- "Context economy is the master skill of AI engineering."
- "Hallucinations are inherent to the architecture, not a bug."

---

### Module 2: Model Types — Chat, Reasoning, and How They Differ
**Time: ~20 min**

A real paradigm shift in 2024–2025: models that "think" before answering. Different cost, latency, and capability profile.

**Key concepts:**
- Standard chat models vs reasoning models (o1, Claude with extended thinking, DeepSeek R1)
- How reasoning models work: chain-of-thought generation as part of inference
- When to use each: chat for fluency, reasoning for hard multi-step problems
- The tradeoffs: reasoning models are slower, more expensive, sometimes overkill
- Brief intro to multimodality (vision, audio) — when it matters
- The model-selection mindset: pick the right tool for the job

**You'll be able to say:**
- "Reasoning models trade latency and cost for correctness on hard problems."
- "Most production traffic should hit cheap, fast models; reserve reasoning for genuinely hard tasks."
- "Multimodality means the same model handles text, images, and increasingly audio."

---

### Module 3: Context Engineering — The Master Skill
**Time: ~25 min**

The shift from "prompt engineering" to curating what actually goes into the model's context.

**Key concepts:**
- System prompts vs user prompts vs conversation history
- Zero-shot, few-shot, and chain-of-thought prompting
- Context as a budget — every token competes for attention
- Common failure modes: lost-in-the-middle, context pollution, instruction drift
- Practical heuristics for clean, effective prompts

**You'll be able to say:**
- "Most prompt 'magic' is just providing the right context clearly."
- "Few-shot examples are usually higher leverage than longer instructions."
- "What I exclude from context matters as much as what I include."

---

### Module 4: RAG — Giving Models Knowledge They Don't Have
**Time: ~25 min**

How to ground LLMs in your own data without retraining them.

**Key concepts:**
- Why RAG exists: context window limits + outdated training data + hallucination
- Embeddings: turning text into vectors that capture meaning
- Vector databases: storing and querying embeddings at scale
- Chunking strategies and why they matter
- Retrieval, reranking, and the full pipeline
- When RAG is the right tool — and when it isn't

**You'll be able to say:**
- "RAG retrieves relevant pieces of knowledge at query time, instead of stuffing everything into context."
- "Embeddings represent meaning as vectors so similarity = closeness."
- "Bad chunking destroys RAG quality more than bad models do."

---

### Module 5: Tools, Function Calling, and MCP
**Time: ~30 min**

How LLMs reach out to the real world — and how that ecosystem is being standardized.

**Key concepts:**
- Function calling: LLMs generate structured tool requests; your system executes
- The basic tool-use loop
- Why tools are the foundation of every "agentic" system
- Structured output and JSON schemas — getting reliable parseable output
- MCP (Model Context Protocol): the "USB for AI tools"
- How MCP makes integrations composable across clients (Cursor, Claude Desktop, etc.)
- Practical patterns: tool design, error handling, naming

**You'll be able to say:**
- "LLMs don't execute tools — they request them via structured output."
- "MCP standardizes how tools and clients connect, like USB or HTTP."
- "Good tool design is API design with extra constraints."

---

### Module 6: Safety, Guardrails, and Prompt Injection
**Time: ~25 min**

The most important security topic for anyone building user-facing AI. Often skipped — and that's why so many production systems are vulnerable.

**Key concepts:**
- Prompt injection: the AI equivalent of SQL injection
- Direct vs indirect injection (poisoned documents, web pages, emails)
- Why injection is unsolved at the model level
- Defense in depth: input filtering, output filtering, sandboxing tools, least-privilege access
- The "two-LLM" pattern and other architectural mitigations
- Jailbreaking vs injection — different threats, different defenses
- Data exfiltration risks when LLMs have tool access

**You'll be able to say:**
- "Prompt injection is unsolved; defense is architectural, not prompt-based."
- "Any user-controlled text that flows into an LLM with tools is a potential attack vector."
- "Least privilege for tools is non-negotiable in production."

---

### Module 7: Agents — Loops, Planning, Reflection
**Time: ~25 min**

What makes something an "agent" and how agentic systems are actually built.

**Key concepts:**
- The basic agent loop: observe → think → act → repeat
- ReAct (Reason + Act) as the foundational pattern
- Planning, reflection, and self-critique
- Subagents and orchestration
- Memory: short-term context vs long-term persistent memory
- Where agents excel — and where they fail in expensive, hard-to-debug ways
- Reliability as the central engineering problem

**You'll be able to say:**
- "An agent is an LLM in a loop with tools and a goal."
- "Reliability, not capability, is the bottleneck for production agents."
- "Subagents are useful when context is heavy and tasks are independent."

---

### Module 8: Skills — Reusable, Composable Instructions
**Time: ~20 min**

How to package repeatable AI behavior into versioned, shareable artifacts.

**Key concepts:**
- The problem skills solve: re-explaining the same instructions every session
- Skill structure: SKILL.md, frontmatter, lazy loading
- Personal vs project vs team skills
- How skills differ from system prompts, tools, and RAG
- Sharing skills across teammates via git
- Cross-tool portability (Cursor, Claude Code, Claude.ai, API)

**You'll be able to say:**
- "Skills are lazily-loaded instruction modules — modular system prompts."
- "The description field decides whether a skill activates; treat it as the most important part."
- "Skills convert tribal knowledge into a versioned, reviewable artifact."

---

### Module 9: Evals & Spec-Driven Development
**Time: ~30 min**

The two emerging disciplines that separate hobbyist AI use from production engineering.

**Key concepts:**
- Why evals are the most underrated topic in AI engineering
- What an eval actually is: inputs, expected behavior, scoring
- Building eval sets that measure what matters
- LLM-as-judge patterns and their pitfalls
- Spec-driven development: specs as the source of truth, code as derived output
- How AI changes the role of the engineer
- The renewed relevance of TDD in an AI-native workflow

**You'll be able to say:**
- "Without evals, prompt and skill changes are guesses."
- "Specs are becoming primary artifacts; code is becoming derived output."
- "The bottleneck is shifting from writing code to specifying intent precisely."

---

### Module 10: Production Considerations — Cost, Latency, Model Selection
**Time: ~30 min**

The engineering side of AI engineering. Where AI work stops being experimentation and starts being systems.

**Key concepts:**
- Cost mechanics: input vs output tokens, model pricing tiers
- Latency: time-to-first-token vs total-time, why streaming matters for UX
- Model routing: send easy queries to cheap models, hard ones to powerful ones
- Prompt caching and how to design prompts to maximize hits
- Batching, async, and parallel patterns
- Open vs closed models: Llama, Mistral, DeepSeek and self-hosting tradeoffs
- When to fine-tune (rarely) vs when to prompt/RAG (almost always)
- Observability: logging, tracing, monitoring LLM systems in production

**You'll be able to say:**
- "Routing simple queries to cheap models is usually the highest-leverage cost optimization."
- "Prompt caching can cut costs by 50–90% with no quality loss when prompts are designed for it."
- "Self-hosting open models makes sense at scale or for data-sensitive workloads — rarely otherwise."

---

## After the Course

You won't be an expert in any single area, but you'll have the durable mental models to:
- Evaluate new tools quickly ("oh, this is just RAG with reranking")
- Decide which augmentation to use for a given problem
- Build small systems end-to-end
- Design for cost, latency, and reliability — not just capability
- Read more advanced material without getting lost

### Recommended next steps

**High-signal sources** (sustainable, low-noise):
- Simon Willison's blog — pragmatic, broad, frequent
- Anthropic's research and engineering posts — framework-defining
- Hamel Husain on evals — best on this topic
- Latent Space podcast — engineering-focused, deep

**Foundational reads:**
- Andrej Karpathy, *"Intro to Large Language Models"* (YouTube, 1 hr)
- Anthropic, *"Building Effective Agents"* (free, ~30 min)
- Rich Sutton, *"The Bitter Lesson"* (essay, ~10 min) — most important essay in the field
- Simon Willison's writing on prompt injection
- Chip Huyen, *Designing Machine Learning Systems* (book) — for production practices

**Practice over reading:**
- Build a 50-line RAG system on your own notes
- Write 2–3 skills for tasks you do at work
- Write evals for one of your skills
- Try building a small agent that does one real task
- Test your own system for prompt injection

**Avoid:** AI Twitter, hype cycles, framework-of-the-week content. The fundamentals don't change that fast.

---

## Progress Tracker

- [ ] Module 1: How LLMs Actually Work
- [ ] Module 2: Model Types — Chat, Reasoning, and How They Differ
- [ ] Module 3: Context Engineering
- [ ] Module 4: RAG
- [ ] Module 5: Tools, Function Calling, and MCP
- [ ] Module 6: Safety, Guardrails, and Prompt Injection
- [ ] Module 7: Agents
- [ ] Module 8: Skills
- [ ] Module 9: Evals & Spec-Driven Development
- [ ] Module 10: Production Considerations
