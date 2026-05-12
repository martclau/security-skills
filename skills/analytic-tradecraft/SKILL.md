---
name: analytic-tradecraft
description: improve analytical reasoning and intelligence-style assessments for ambiguous, incomplete, or contested questions. use when needed to frame a problem, surface assumptions, challenge mental models, compare hypotheses, assess evidence quality, watch for bias and deception, generate indicators or alternative futures, or write concise audience-focused analysis with explicit confidence, uncertainties, and signposts.
---

Use structured analytic tradecraft by default. Treat analysis as a reasoning process that must be made visible, not just a conclusion to be stated. Prefer explicit assumptions, competing explanations, evidence-quality checks, and clear uncertainty language over fluent but unsupported narrative.

## Core operating principles

- Start by stating the analytic question in one sentence.
- State the audience and decision need if it is known. If not known, assume the audience wants a short decision-support assessment.
- Externalize the reasoning. Use lists, matrices, or tables for assumptions, hypotheses, evidence, and signposts instead of keeping the model implicit.
- Assume mental models are useful but hazardous. Challenge and revise them instead of defending them.
- Seek disconfirming evidence, not only confirming evidence.
- Treat more information as a mixed blessing. More data can increase confidence without increasing accuracy.
- Prefer a small set of plausible hypotheses over a single early answer.
- Make uncertainty explicit: what is known, inferred, missing, and speculative.
- Write for the reader. Favor direct prose, short paragraphs, and clear bottom lines.

## Standard workflow

Follow this sequence unless the user asks for something narrower.

1. **Frame the problem**
   - Rewrite the question as a precise analytic problem.
   - Define scope, time horizon, unit of analysis, and what would count as an answer.
   - Note whether this is explanatory, estimative, warning, red-team, or decision-support analysis.

2. **Surface assumptions**
   - List the working assumptions that must be true for the current line of reasoning to hold.
   - Mark each as: high confidence / medium confidence / low confidence.
   - For each assumption, note what evidence or event would weaken it.

3. **Generate hypotheses**
   - Produce 3 to 5 plausible hypotheses or explanations.
   - Include at least one non-obvious or contrarian hypothesis when the problem is ambiguous.
   - Avoid collapsing hypotheses too early.

4. **Evaluate evidence quality**
   - Separate evidence from interpretation.
   - For each critical item, note source quality, ambiguity, corroboration, timeliness, and possible deception or selection effects.
   - Flag intelligence gaps explicitly.

5. **Run ACH-lite unless a deeper method is requested**
   - Build a compact matrix of hypotheses vs evidence.
   - Mark each item as consistent, inconsistent, or not diagnostic.
   - Weight disconfirming evidence more heavily than confirming evidence.
   - Prefer the hypothesis with the least serious inconsistency, not the one with the most supporting anecdotes.

6. **Check for bias and alternative perspectives**
   - Test for confirmation bias, anchoring, mirror-imaging, overconfidence, availability, and premature closure.
   - Ask: what would I believe if the opposite outcome occurred?
   - If the issue involves an adversary, competitor, or foreign actor, include a brief perspective shift from that actor's viewpoint.

7. **Develop indicators and signposts**
   - Identify observable developments that would increase or decrease confidence in each leading hypothesis.
   - Distinguish current evidence from forward-looking indicators.

8. **Draft the assessment**
   - Lead with the bottom line.
   - Then provide reasoning, key assumptions, confidence, major alternatives, and signposts.
   - End with what could change the judgment.

## Minimum viable mode

Use this compressed format when the user needs a fast answer:

- Question
- Main judgment
- Confidence and why
- 2 to 4 key assumptions
- Best alternative explanation
- 3 most diagnostic evidence points
- 3 signposts to watch

## Deeper techniques to invoke selectively

Use these when they fit the task:

- **Key assumptions check** for hidden premises or brittle logic.
- **Quality of information check** when source reliability or ambiguity is central.
- **Indicators or signposts** for warning, monitoring, and updateable judgments.
- **Analysis of competing hypotheses** for contested explanations.
- **Devil's advocacy / Team A-Team B / red team** when a consensus is entrenched.
- **High-impact / low-probability** when rare outcomes matter.
- **What if?** when stress-testing a policy or plan.
- **Brainstorming / outside-in thinking** at the start of a project.
- **Alternative futures** when the environment is dynamic and path dependent.

## Writing rules

- Write as if the reader has limited working memory and limited time.
- Use headings that convey meaning, not generic labels.
- Prefer one claim per paragraph.
- Distinguish clearly among facts, inferences, assumptions, and judgments.
- Do not hide uncertainty in vague prose. State it directly.
- Do not overwhelm the reader with raw data; extract what is diagnostic.
- If the user asks for a memo, brief, or executive summary, adapt format but preserve the tradecraft steps.

## Anti-patterns to avoid

Do not:

- default to a single favored hypothesis without testing alternatives.
- treat volume of evidence as equivalent to diagnostic value.
- confuse consistency with truth.
- assume absence of evidence is evidence of absence when denial or deception is plausible.
- project your own values or incentives onto another actor without argument.
- let polished language replace explicit reasoning.
- bury key assumptions or confidence behind passive voice.

## Output contract

Unless the user requests another format, produce sections in this order:

1. main judgment
2. confidence
3. key assumptions
4. leading hypotheses or alternatives
5. evidence and reasoning
6. indicators / signposts
7. what could change the judgment

## Optional references bundled with this skill

Read these only when needed:

- `references/book-synthesis.md` for the conceptual basis and technique map.
- `references/output-template.md` for a reusable response template.

