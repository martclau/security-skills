---
name: c-build-test-review
description: Review C/C++ build configurations, compiler flags, assertion usage, test setups, and analysis tooling against established best practices for safety, security, and correctness. Use this skill whenever the user asks to audit, review, critique, or harden a C/C++ project's Makefile, CMakeLists.txt, build script, compiler invocation, GCC/Clang/MSVC flags, security hardening, unit tests, static analysis, or dynamic analysis configuration. Trigger even on casual phrasing like "are my GCC flags any good", "is this build secure", "what's missing from my C testing", "should I be using sanitizers", or whenever a C/C++ project is being reviewed and build/test quality is in scope. Also trigger when reviewing how `assert` and `static_assert` are used in C code.
---

# C Build & Test Review

A structured review skill for evaluating a C (or C++) project's build configuration, assertion discipline, testing infrastructure, and analysis tooling against modern best practices. The goal is not to rewrite the project but to identify concrete gaps and produce an actionable, prioritized review.

## When to use

Use this skill when the user shares any of the following and asks for a review, audit, or improvement suggestions:

- A Makefile, CMakeLists.txt, Meson script, build.ninja, or shell build script
- A raw `gcc`/`clang`/`cl.exe` command line
- A CI configuration (GitHub Actions, GitLab CI, etc.) for a C/C++ project
- Source code where assertions, tests, or sanitizer setup is part of the question
- A C/C++ project repository where they want to "harden" or "modernize" the build

Do **not** use this skill for pure code-correctness reviews unrelated to build/test configuration, or for languages other than C/C++.

## Core mental model: four review axes × five SDLC phases

A good review looks at **four independent concern areas**:

1. **Compiler flag hygiene** — warnings, language standard, optimization, debug info, security hardening
2. **Assertion discipline** — `static_assert` for compile-time invariants, `assert` for development-time invariants, neither for runtime error handling
3. **Testing infrastructure** — unit-test framework, coverage of normal *and* error paths, test-only build configuration
4. **Analysis tooling** — static analyzers (compile-time) and sanitizers / dynamic analysis (run-time)

These axes are evaluated **per SDLC phase**, because what is correct for one phase is wrong for another:

| Phase | Goal | Optimization | Debug info | Assertions | Sanitizers | Hardening |
|---|---|---|---|---|---|---|
| **Build** | Catch defects via compiler diagnostics | `-O2` (GCC needs it for many warnings) | minimal | enabled | off | on |
| **Debug** | Edit-compile-debug cycle | `-O0` or `-Og` | `-g3` | enabled | optional | off (interferes) |
| **Test** | Find defects via runtime instrumentation | `-O1`/`-Og` | `-g3` | enabled | **on** | off (interferes) |
| **PGO** | Collect/use profile data | `-O2` + PGO flags | minimal | enabled | off | on |
| **Release** | Deploy to production | `-O2` / `-O3` / `-Os` | minimal or stripped | **disabled** (`-DNDEBUG`) | off | **on** |

A project that uses one flag set for everything is itself a finding — different phases should have different configurations.

## Workflow

When invoked, follow these steps:

### 1. Inventory what you have

Before producing recommendations, identify:

- **Build system** (Make, CMake, Meson, raw shell, MSBuild)
- **Compiler(s)** in use (GCC, Clang, MSVC, ICC) and their target versions
- **Language standard** in use (C89/C99/C11/C17/C23, or unspecified)
- **Phases configured** (single config? Debug+Release? something more granular?)
- **Test framework** (Google Test, CUnit, Unity, CppUnit, custom, none)
- **Analyzers / sanitizers** referenced (ASan, UBSan, TSan, MSan, `-fanalyzer`, `/analyze`, clang-tidy, CodeQL, Coverity, etc.)
- **Assertion usage in source** (any `static_assert`? any `assert`? is `NDEBUG` controlled?)

If anything is missing or ambiguous, state it explicitly in the review rather than assuming.

### 2. Evaluate each axis against the phase

For each (axis, phase) pair, check the configuration against the recommendations in `## Reference: recommended flags` below. Note both **what is present** and **what is missing** — omissions are findings.

### 3. Produce a structured review

Use the output format in `## Review output format` below. Findings must be:

- **Categorized by severity** (critical / important / nice-to-have)
- **Specific** — quote the exact flag, line, or omission
- **Actionable** — say what to add, remove, or change, with the concrete replacement
- **Justified** — explain *why* in one sentence, referencing the underlying property (e.g., "ASLR requires position-independent code", "many GCC diagnostics only fire at `-O2`")

Never recommend a change without saying why. A reviewer who only says "add `-Wall`" is not useful; one who says "add `-Wall` because the compiler currently emits only the most conservative warnings and is silently accepting code patterns that frequently hide defects" is.

### 4. Surface phase-mismatch hazards explicitly

Some configurations are individually fine but combine badly. Call these out:

- `-D_FORTIFY_SOURCE` set with `-O0` → silently does nothing; `_FORTIFY_SOURCE` requires optimization
- `-fsanitize=address` left on in the release build → large runtime/memory overhead, not intended for production
- `NDEBUG` defined in the test build → disables `assert`, defeating one of the main purposes of the test phase
- No `-fpie -pie` but the project is a main executable that wants ASLR → linker silently produces a non-PIE binary
- `-Werror` in release but not in build/CI → defects merge to main and only break the release pipeline
- Sanitizers enabled in the *build* (compilation/analysis) phase → can cause false positives from the inserted runtime instrumentation

### 5. Recommend, don't rewrite

Unless the user explicitly asks for a rewritten Makefile/CMakeLists.txt, the output is a **review**, not a patch. List the changes; let the user apply them. If they ask for a corrected file afterward, then produce it.

## Reference: recommended flags

### GCC and Clang

Apply most of these in build/test/release. Adjust for the debug phase as noted.

| Flag | Purpose | Notes |
|---|---|---|
| `-std=c23` (or `-std=c2x` on older compilers) | Pin the language standard | Default `gnu17` on GCC 13 introduces extensions that may conflict with the standard; pin explicitly for portability |
| `-pedantic` | Warn on non-conforming code | Pair with `-std=` |
| `-Wall` | Enable the conservative recommended warning set | Despite the name, not all warnings |
| `-Wextra` | Enable the next tier of warnings | |
| `-Wconversion` | Warn on implicit value-altering conversions | Catches many integer-truncation and sign-conversion bugs; can be noisy initially |
| `-Werror` | Promote warnings to errors | Forces warnings to be addressed before merge |
| `-O2` | Enable optimization (and many additional GCC diagnostics) | `-Os`/`-Oz` for size; `-O0` or `-Og` for debug only |
| `-g3` | Generate maximal debugging info (including macros) | Use `-ggdb3` if exclusively debugging with GDB |
| `-D_FORTIFY_SOURCE=2` | Compile-time + runtime buffer-overflow checks in libc | Requires optimization; use `=3` with GCC ≥ 12 + glibc ≥ 2.34; disable for unoptimized debug builds |
| `-fstack-protector-strong` | Add stack canaries to functions likely to be exploited | Balance between `-fstack-protector` (too weak) and `-fstack-protector-all` (excessive) |
| `-fpie -Wl,-pie` | Build a position-independent **executable** (enables ASLR) | For the main program |
| `-fpic -shared` | Position-independent **shared library** | For `.so` / `.dylib` targets |
| `-Wl,-z,noexecstack` | Mark the stack non-executable (W^X) | Linker flag |

**Sanitizers** (test phase only — do not ship):

| Flag | Purpose |
|---|---|
| `-fsanitize=address` | AddressSanitizer: heap/stack/global overflows, UAF, leaks |
| `-fsanitize=undefined` | UBSan: signed overflow, alignment, OOB shifts, etc. |
| `-fsanitize=thread` | TSan: data races (mutually exclusive with ASan) |
| `-fsanitize=memory` | MSan: uninitialized reads (Clang only) |
| `-fno-omit-frame-pointer` | Better sanitizer stack traces |
| `-fno-common` | Allows ASan to instrument globals |

Sanitizer flags must be passed to **both** the compiler and the linker.

**Static analysis** (in addition to compiler warnings):

- GCC ≥ 10: `-fanalyzer`
- Clang: `clang --analyze` or `scan-build`
- Third-party: clang-tidy, CodeQL, Coverity, SonarQube, Helix QAC, LDRA, TrustInSoft

### Visual C++ (MSVC)

| Flag | Purpose | GCC/Clang equivalent |
|---|---|---|
| `/std:clatest` | Latest C language features | `-std=c23` |
| `/permissive-` | Strict conformance mode | `-pedantic` + strict `-std=` |
| `/W4` | High warning level (recommended) | `~ -Wall -Wextra` |
| `/WX` | Warnings as errors | `-Werror` |
| `/O2` | Optimize for speed | `-O2` |
| `/Od` | Disable optimization (debug) | `-O0` |
| `/sdl` | Additional security checks (SDL features) | partial overlap with `-fstack-protector-strong` + fortify |
| `/guard:cf` | Control Flow Guard (compiler **and** linker) | no direct equivalent; partial overlap with `-fcf-protection` |
| `/analyze` | Built-in static analyzer | `-fanalyzer` |

Avoid `/Wall` on MSVC — it generates a large number of false positives from system headers.

## Reference: assertion discipline

A reviewer should check that assertions are used for the right things:

**`static_assert` (compile-time)** — use for invariants the compiler can verify:

- Structure layout assumptions (`sizeof(struct) == expected`, no padding)
- Type-size assumptions (`sizeof(unsigned char) < sizeof(int)` for `getchar`/`EOF` correctness)
- Buffer-size relationships at fixed sizes (`sizeof(dest) > sizeof(src)`)
- ABI and platform assumptions

Place the assertion physically next to the code that depends on it, so a maintainer who violates the invariant sees the diagnostic point at the relevant site.

**`assert` (runtime, development-only)** — use for programming-error invariants:

- Preconditions (caller contract: pointer non-null, size in range)
- Postconditions
- Loop / data-structure invariants

Be aware that `assert` becomes `((void)0)` when `NDEBUG` is defined. Therefore `assert` must **never** be used for:

- Validating untrusted input
- Checking I/O / system-call return values
- Checking dynamic allocation success
- Checking permissions
- Anything that can legitimately fail at runtime

Those are *normal error paths* and require always-on error handling, not assertions.

A useful pattern: `assert(precondition && "human-readable message")`. The string literal is non-null, so the `&&` is always evaluated as the predicate alone, and the message appears in the failure output.

**Common findings to flag:**

- `assert` used for input validation or error checking → replace with real error handling
- No `static_assert` anywhere in a project with structure-layout, type-size, or buffer-size assumptions → add them at the assumption sites
- `NDEBUG` defined in a "test" or "debug" build → disables `assert`, almost certainly wrong
- `NDEBUG` *not* defined in the release build → `assert` failures will abort production processes

## Reference: testing infrastructure

Things to look for and flag:

- **No unit-test framework at all** → recommend one (Google Test if C++ harness is acceptable; Unity or CUnit for pure C)
- **Tests build with release flags** → tests should run with `-g3`, low optimization, and sanitizers on
- **Tests only exercise happy paths** → flag missing error-path coverage explicitly; the chapter's `get_error` example is the canonical case of "tests passed but the error branch was never exercised, and there was a real bug there"
- **Tests don't run in CI** → flag this; tests that aren't continuously run rot
- **Tests don't run under sanitizers in CI** → flag this; one of the highest-value low-effort additions to almost any C project
- **`extern "C"`** missing around C headers in a C++ test harness (e.g., Google Test) → linker errors due to name mangling
- **No discoverable test target** in the build system (e.g., no `enable_testing()` + `gtest_discover_tests()` in CMake, no `make test` target) → tests exist but are not wired into the standard developer workflow

## Reference: static and dynamic analysis

**Static analysis** complements but does not replace compiler warnings. A clean compile at `-Wall -Wextra -Werror` is the baseline; static analyzers find what the compiler doesn't:

- Inter-procedural data-flow defects
- Path-sensitive null-pointer dereferences
- Resource leaks across functions
- API-misuse patterns

A reviewer should flag any nontrivial C project that has **no** static analysis configured. Suggested entry points by ease of adoption:

1. `-fanalyzer` (GCC ≥ 10) or `clang --analyze` — zero extra installation
2. `clang-tidy` with a curated check set (e.g., `bugprone-*`, `cert-*`)
3. `/analyze` for MSVC projects
4. CodeQL for projects on GitHub
5. Commercial tools for safety/security-critical code

**Dynamic analysis** (sanitizers) is generally higher-value-per-effort than static analysis because it has a much lower false-positive rate — if ASan or UBSan reports something, it's almost certainly real. The trade-off is that it requires test coverage to find the bug (an unexecuted line of code won't be caught).

Sanitizer combinations that work together:
- ASan + UBSan + LSan — safe to enable simultaneously
- TSan — must be run separately (incompatible with ASan)
- MSan — must be run separately, Clang-only, requires instrumented libc++

A typical recommendation: run the test suite three times in CI — once under ASan+UBSan, once under TSan, once without sanitizers for raw timing.

## Review output format

ALWAYS structure the review using this exact template (omit empty sections):

```
# Build & Test Review: <project name>

## Summary
<2–4 sentences: overall posture, the single highest-impact change>

## Inventory
- Build system: ...
- Compiler(s) / standard: ...
- Phases configured: ...
- Test framework: ...
- Analyzers / sanitizers in use: ...
- Assertion usage: ...

## Findings

### Critical
<Issues that allow defects or vulnerabilities to ship, or that defeat the build's stated goal>
- **<short title>** — <description>. *Why it matters:* <one sentence>. *Recommended change:* <concrete replacement>.

### Important
<Issues that meaningfully reduce the project's ability to catch defects>
- ...

### Nice-to-have
<Polish, modernization, and ergonomic improvements>
- ...

## Phase-by-phase recommended flag set
<A small table or block showing what the build / debug / test / release configurations should look like for this specific project, given what was inventoried>

## Suggested next steps
<3–5 ordered, actionable steps the user can take in order of impact-per-effort>
```

Findings inside each severity should be ordered by impact, not by where they appear in the file.

## What good looks like

A complete review should leave the user with:

1. A clear picture of what their build currently does and doesn't do
2. A small number of high-impact changes, separated from polish
3. Concrete flag-by-flag replacements they can paste in
4. An explanation of *why* each change matters, in terms of the property it protects (defect detection, exploit mitigation, debuggability, etc.)

If the review is just a list of flags with no rationale and no phase awareness, it has not used this skill correctly.

## References

- `references/worked-example.md` — a complete worked review of a small Makefile-based project, showing the expected shape and tone of the output. Read this when the workflow feels abstract or when you want to calibrate severity tiering and the level of justification expected per finding.

## What this skill does not cover

- General code review unrelated to build/test (logic bugs, API design, style)
- Build-system migration advice (e.g., "should I switch from Make to CMake")
- Cross-compilation, embedded toolchains, or RTOS-specific flag sets
- Languages other than C and C++ (Rust, Zig, etc. — different toolchains, different conventions)

If the user's request is primarily one of these, say so and pivot rather than forcing this skill onto it.
