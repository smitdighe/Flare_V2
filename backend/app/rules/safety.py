"""Bounded regex for the `contains` operator. PLAN §9 / CONTRACT RuleCondition.

`contains` compiles a value a USER TYPED INTO A WEB FORM as a regular
expression. That is a denial-of-service primitive unless it is bounded, and
CPython's `re` cannot be interrupted once a match starts — a catastrophic
backtrack pins a worker thread until it finishes, which on a single-process
demo server means the whole API stops answering.

THREE BOUNDS, AT TWO DIFFERENT TIMES.

**At rule creation** (`compile_pattern`), two static bounds:

  * a LENGTH cap, because a long pattern is both harder to reason about and
    cheaper to make pathological;
  * a STRUCTURAL check for nested quantifiers — a quantifier applied to a group
    whose body itself contains a quantifier or an alternation. `(a+)+`,
    `(a|a)*` and `(?:a|aa)+` are the classic exponential shapes, and all three
    match that description. Rejection happens at CREATE time with a message the
    frozen UI renders verbatim through its `detail` path, so the operator finds
    out while writing the rule rather than when the feed stalls.

**At match time** (`safe_search`), two dynamic bounds:

  * the SUBJECT is truncated, because backtracking cost grows with input
    length and an alert signature is attacker-influenced text;
  * the match carries a real TIMEOUT. This is why the module uses `regex`
    rather than the standard library: `regex` checks a deadline inside its
    matching loop and raises, and `re` offers nothing equivalent. A timeout is
    a FALSE condition that is RECORDED — never a silent false, and never an
    exception that takes the rules stage down.

The static check is deliberately conservative and will refuse some patterns
that would have been fine. That trade is taken knowingly: the cost of a false
rejection is an operator rewriting a rule, and the cost of a false acceptance
is the API hanging in front of an audience.
"""

from __future__ import annotations

from dataclasses import dataclass

import regex

QUANTIFIERS = frozenset("*+?{")


class PatternTooComplex(ValueError):
    """A user-supplied pattern failed a static bound. Surfaces as a 422."""


@dataclass(frozen=True)
class MatchOutcome:
    """The result of one bounded match.

    `timed_out` is carried separately from `matched` so the condition trace can
    say "this did not match because it ran out of time", which is a different
    fact from "this did not match".
    """

    matched: bool
    timed_out: bool = False
    note: str | None = None


def _scan_complexity(pattern: str, max_quantifiers: int) -> None:
    """Reject nested quantifiers and quantifier spam.

    A single left-to-right pass with a stack of open groups. Each stack frame
    remembers whether the group's body has so far contained a quantifier or a
    top-level alternation; when the group closes and is immediately quantified,
    that flag is what makes it a nested quantifier.

    Character classes are skipped wholesale: `[*+]` is two literals, not two
    quantifiers, and counting them would reject ordinary patterns.
    """
    quantifier_count = 0
    # Each frame: [contains_quantifier_or_alternation]
    stack: list[bool] = []
    top_level_risky = False

    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]

        if char == "\\":
            # An escaped character is a literal, whatever it is.
            index += 2
            continue

        if char == "[":
            close = pattern.find("]", index + 1)
            index = length if close == -1 else close + 1
            continue

        if char == "(":
            stack.append(False)
            index += 1
            continue

        if char == "|":
            if stack:
                stack[-1] = True
            else:
                top_level_risky = True
            index += 1
            continue

        if char == ")":
            body_risky = stack.pop() if stack else False
            next_char = pattern[index + 1] if index + 1 < length else ""
            if next_char in QUANTIFIERS and body_risky:
                raise PatternTooComplex(
                    "This pattern nests one repetition inside another "
                    f"(near {pattern[max(0, index - 12) : index + 2]!r}). Shapes "
                    "like (a+)+ or (a|a)* can take exponential time on input "
                    "that almost matches, which would stall alert processing. "
                    "Rewrite it without a repeated group, or use a plain "
                    "substring."
                )
            if next_char in QUANTIFIERS or body_risky:
                # The group is itself a repeated or alternating unit, so an
                # enclosing quantifier would nest.
                if stack:
                    stack[-1] = stack[-1] or next_char in QUANTIFIERS or body_risky
                else:
                    top_level_risky = top_level_risky or body_risky
            index += 1
            continue

        if char in QUANTIFIERS:
            quantifier_count += 1
            if quantifier_count > max_quantifiers:
                raise PatternTooComplex(
                    f"This pattern uses more than {max_quantifiers} repetition "
                    "operators. Repetition is where regular-expression blow-ups "
                    "come from, so the number of them is capped."
                )
            if stack:
                stack[-1] = True
            index += 1
            continue

        index += 1

    # `top_level_risky` is read only to keep the alternation branch meaningful
    # for patterns with no groups at all; a bare `a|b` is safe on its own.
    del top_level_risky


def compile_pattern(
    pattern: str, *, max_length: int, max_quantifiers: int
) -> regex.Pattern[str]:
    """Static bounds, then compile. Raises PatternTooComplex on rejection."""
    if not isinstance(pattern, str) or not pattern:
        raise PatternTooComplex("A `contains` condition needs a non-empty value.")
    if len(pattern) > max_length:
        raise PatternTooComplex(
            f"This pattern is {len(pattern)} characters; the limit is "
            f"{max_length}."
        )

    _scan_complexity(pattern, max_quantifiers)

    try:
        return regex.compile(pattern, regex.IGNORECASE)
    except regex.error as exc:
        raise PatternTooComplex(
            f"This is not a valid pattern: {exc}"
        ) from exc


def safe_search(
    compiled: regex.Pattern[str],
    subject: str,
    *,
    timeout_seconds: float,
    max_subject_length: int,
) -> MatchOutcome:
    """One bounded match. A timeout is a recorded FALSE, never a raise."""
    truncated = subject[:max_subject_length]
    try:
        found = compiled.search(truncated, timeout=timeout_seconds) is not None
    except TimeoutError:
        return MatchOutcome(
            matched=False,
            timed_out=True,
            note=(
                f"the pattern did not finish within {timeout_seconds * 1000:.0f}ms "
                "on this value, so the condition is treated as NOT matching. A "
                "rule that cannot be evaluated does not get to change a verdict."
            ),
        )
    note = None
    if len(subject) > max_subject_length:
        note = (
            f"matched against the first {max_subject_length} characters of a "
            f"{len(subject)}-character value"
        )
    return MatchOutcome(matched=found, note=note)
