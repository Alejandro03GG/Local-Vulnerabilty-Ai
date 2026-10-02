"""Standard decision questions for evaluating vulnerability matches."""

from __future__ import annotations

from vuln_ai.ai.models import DecisionQuestion, QuestionType


def get_default_decision_questions() -> list[DecisionQuestion]:
    """Return the standard set of decision questions for vulnerability assessment.

    Dimensions:
    1. Applicability (noul): Probabilistic evaluation of whether the CVE applies to the component.
    2. Exposure (choice): Direct usage, indirect dependency, or unknown.
    3. Urgency (score): Remediation / investigation priority on a 1-10 scale.

    Semantics Reminder:
    Probabilities produced represent model evaluation of the choices given the context.
    They do not represent real-world mathematical certainty of exploitability.
    """
    return [
        DecisionQuestion(
            id="applicability",
            question="Given the component name, version, and catalog details, is this vulnerability applicable?",
            question_type=QuestionType.NOUL,
        ),
        DecisionQuestion(
            id="exposure",
            question="What is the exposure posture of this component in the declared manifest?",
            question_type=QuestionType.CHOICE,
            options=["direct", "indirect", "unknown"],
        ),
        DecisionQuestion(
            id="urgency",
            question="What is the recommended remediation and triage urgency priority (1 to 10)?",
            question_type=QuestionType.SCORE,
            min_score=1.0,
            max_score=10.0,
        ),
    ]
