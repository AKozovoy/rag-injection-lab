"""Defense #15: check the model's answer before the user sees it.

It reuses the #11 detectors, so it catches exactly what they catch: links
outside the allowlist and the secret. It can't catch false answers, which look
like normal text, or anything the detectors miss (e.g. a secret spelled out in words).
"""

from detectors import detect_secret, find_disallowed_links

# Shown instead of an answer that contains the secret. Product decision.
BLOCKED_MESSAGE = "Sorry, I can't share that. Please ask a Northwind support question."
LINK_PLACEHOLDER = "[link removed]"


def filter_output(answer: str) -> tuple[str, list[dict]]:
    """Return the filtered answer and a list of what the filter did (empty = unchanged)."""
    # Block the whole answer: removing just the code could leave hints around it.
    if detect_secret(answer):
        return BLOCKED_MESSAGE, [{"action": "blocked_secret"}]

    actions = []
    # Cut from the end backwards, so earlier start/end positions stay valid.
    for start, end, domain in reversed(find_disallowed_links(answer)):
        answer = answer[:start] + LINK_PLACEHOLDER + answer[end:]
        actions.insert(0, {"action": "link_removed", "domain": domain})
    return answer, actions


def describe_actions(actions: list[dict]) -> str:
    """One readable line, e.g. "link removed (evil.example)"."""
    parts = []
    for a in actions:
        if a["action"] == "blocked_secret":
            parts.append("answer blocked (secret)")
        elif a["action"] == "link_removed":
            parts.append(f"link removed ({a['domain']})")
    return ", ".join(parts)
