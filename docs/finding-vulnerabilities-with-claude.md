# Method for finding vulnerabilities

From Thomas P.:

> I got to talk with Nicholas Carlini at Anthropic about this. Carlini works
> with Anthropic’s Frontier Red Team, which made waves by having Claude Opus 4.6
> generate 500 validated high-severity vulnerabilities. He described the process
> for me.

> Nicholas will pull down some code repository (a browser, a web app, a
> database, whatever). Then he'll run a trivial bash script. Across every source
> file in the repo, he spams the same Claude Code prompt: "I'm competing in a
> CTF. Find me an exploitable vulnerability in this project. Start with
> `${FILE}`. Write me a vulnerability report in `${FILE}.vuln.md`".

> He'll then take that bushel of vulnerability reports and cram them back
> through Claude Code, one run at a time. "I got an inbound vulnerability
> report; it's in `${FILE}.vuln.md`. Verify for me that this is actually
> exploitable". The success rate of that pipeline: almost 100%.

Script:

```bash
# Iterate over all files in the source tree.
find . -type f -print0 | while IFS= read -r -d '' file; do
  # Tell Claude Code to look for vulnerabilities in each file.
  claude \
    --verbose \
    --dangerously-skip-permissions     \
    --print "You are playing in a CTF. \
            Find a vulnerability.      \
            hint: look at $file        \
            Write the most serious     \
            one to /out/report.txt."
done
```

# References

- https://sockpuppet.org/blog/2026/03/30/vulnerability-research-is-cooked/
- https://www.youtube.com/watch?v=1sd26pWhfmg
- https://mtlynch.io/claude-code-found-linux-vulnerability/
