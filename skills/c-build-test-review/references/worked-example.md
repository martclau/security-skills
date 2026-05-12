# Worked Example: Reviewing a Typical C Project

Read this when the SKILL.md workflow feels abstract and you want to see what a finished review looks like end-to-end. The point is the *shape* of the review, not the specific findings.

## The input

A user shares this Makefile and asks "can you review my build setup?":

```make
CC = gcc
CFLAGS = -O2 -Wall

SRCS = main.c parser.c hash.c
OBJS = $(SRCS:.c=.o)

myapp: $(OBJS)
	$(CC) $(CFLAGS) -o myapp $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: myapp
	./myapp < test_input.txt > test_output.txt
	diff test_output.txt test_expected.txt

clean:
	rm -f myapp $(OBJS)

.PHONY: test clean
```

And the user mentions they have `assert(input != NULL)` calls scattered in their code.

## The review (following the template)

```
# Build & Test Review: myapp

## Summary
The build uses a single configuration for all purposes, which is the largest structural issue: there is no separation between a development build (debug info, assertions on, sanitizers) and a release build (optimized, hardened, assertions off). Diagnostic coverage is also minimal — `-Wall` alone misses many useful warnings. The "test" target is a single integration check with no unit-test framework. Highest-impact change: split the build into Debug/Release and add `-Wextra -Wconversion -Werror -std=c23`.

## Inventory
- Build system: plain Make
- Compiler(s) / standard: gcc, no `-std=` specified (defaults to `gnu17`)
- Phases configured: one (no separation of debug/test/release)
- Test framework: none — single end-to-end diff comparison
- Analyzers / sanitizers in use: none
- Assertion usage: runtime `assert` only; no `static_assert`; `NDEBUG` not controlled by build

## Findings

### Critical

- **No security hardening on the production binary** — the executable is built without ASLR-enabling flags, stack canaries, fortified libc, or non-executable stack. *Why it matters:* these are essentially free at runtime and defeat entire classes of memory-corruption exploits. *Recommended change:* for the release configuration add `-fpie -Wl,-pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,noexecstack`.

- **Language standard is unpinned** — `gcc` defaults to `gnu17`, which adds GNU extensions that can silently make code non-portable. *Why it matters:* a future compiler change could alter semantics; portability to Clang/MSVC is not validated. *Recommended change:* add `-std=c23` (or `-std=c2x` if your GCC is too old) and `-pedantic`.

### Important

- **`-Wall` is the only warning flag** — the compiler is being asked to flag only its most conservative set of issues. *Why it matters:* many high-value diagnostics (sign-conversion, value-altering implicit conversions, extra format checks) are off. *Recommended change:* add `-Wextra -Wconversion`, and `-Werror` so they cannot be ignored.

- **No debug build configuration** — there is no way to build with `-O0 -g3` for the edit-compile-debug cycle. *Why it matters:* debugging optimized code is significantly harder, and `-g3` is required to expand macros in GDB. *Recommended change:* introduce a `make debug` (or BUILD=debug) target with `-O0 -g3` and assertions on.

- **No sanitizer build** — there is no way to run the program under AddressSanitizer or UndefinedBehaviorSanitizer. *Why it matters:* these have very low false-positive rates and routinely catch latent memory and UB bugs that no compiler warning will find. *Recommended change:* add a sanitizer target compiling with `-fsanitize=address,undefined -fno-omit-frame-pointer -g3 -O1` and linking with the same flags.

- **No unit-test framework** — the only test is an integration-level diff comparison, which doesn't isolate failures or exercise internal error paths. *Why it matters:* when a regression occurs, you'll know *that* something is wrong but not *where*; error-handling branches are unlikely to be exercised at all. *Recommended change:* add Unity (pure C) or Google Test (C++ harness) and start with unit tests for `parser.c` and `hash.c`.

- **`assert` is used without controlling `NDEBUG`** — assertions will currently fire in production. *Why it matters:* assertions are for development-time invariants; in production they cause hard crashes on internal-bug conditions and should typically be disabled. Conversely, you also need to ensure they remain *on* during testing. *Recommended change:* explicitly define `-DNDEBUG` in the release configuration and ensure it is **not** defined in debug/test.

### Nice-to-have

- **No `static_assert` for layout/size assumptions** — the project has hash tables and a parser, which often carry assumptions like "this struct is exactly 32 bytes" or "this enum fits in 16 bits". *Recommended change:* add `static_assert` calls at the points where these assumptions are made.

- **No static analyzer in the build** — GCC 10+ ships with `-fanalyzer` which is free to enable. *Recommended change:* add a `make analyze` target that runs `gcc -fanalyzer` on the sources.

- **Build system makes phase separation awkward** — Make is fine, but each new configuration multiplies the boilerplate. *Recommended change:* if the project is likely to grow, consider migrating to CMake which expresses build configurations natively.

## Phase-by-phase recommended flag set

```make
# Shared
WARN    = -Wall -Wextra -Wconversion -Werror -pedantic
STD     = -std=c23

# Debug
DEBUG_CFLAGS   = $(STD) $(WARN) -O0 -g3
# (no NDEBUG; assertions on)

# Test (sanitized)
TEST_CFLAGS    = $(STD) $(WARN) -O1 -g3 \
                 -fsanitize=address,undefined \
                 -fno-omit-frame-pointer -fno-common
TEST_LDFLAGS   = -fsanitize=address,undefined

# Release
REL_CFLAGS     = $(STD) $(WARN) -O2 -DNDEBUG \
                 -D_FORTIFY_SOURCE=2 \
                 -fstack-protector-strong \
                 -fpie
REL_LDFLAGS    = -Wl,-pie -Wl,-z,noexecstack
```

## Suggested next steps

1. Add the warning flags and `-std=c23`; fix anything that lights up. This is the highest impact-per-effort change in the entire review.
2. Split the Makefile into debug/test/release configurations (even if minimal at first).
3. Add an ASan+UBSan test target and run the existing diff test under it — you will likely find at least one real bug.
4. Add the release hardening flags (`-D_FORTIFY_SOURCE=2`, `-fstack-protector-strong`, `-fpie -pie`, `-Wl,-z,noexecstack`).
5. Introduce a unit-test framework and write tests for the error paths in `parser.c` and `hash.c`.
```

## What the example illustrates

- **Severity is genuinely tiered.** Missing hardening on a deployed binary is critical; missing `-Wconversion` is important; missing `static_assert` is nice-to-have. Don't flatten everything to "you should add X".
- **Every finding has a "Why it matters".** A flag list without rationale is not a review.
- **Phase awareness is concrete.** The recommended flag set explicitly distinguishes debug / test / release rather than dumping all flags into one bag.
- **Next steps are ordered by impact-per-effort**, not by the order findings appear in the file.
- **The review didn't rewrite the Makefile.** It made the changes explicit and let the user apply them.
