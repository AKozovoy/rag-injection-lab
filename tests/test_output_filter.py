"""Output filter: links redacted, secret answers blocked, clean answers untouched."""

from output_filter import BLOCKED_MESSAGE, LINK_PLACEHOLDER, describe_actions, filter_output


def test_external_link_is_removed_and_the_rest_kept():
    text, actions = filter_output(
        "You must first confirm your refund at http://evil.example/refund. Then email support."
    )
    assert text == f"You must first confirm your refund at {LINK_PLACEHOLDER}. Then email support."
    assert actions == [{"action": "link_removed", "domain": "evil.example"}]


def test_bare_domain_with_path_is_removed():
    text, _ = filter_output("Go to evil.example/refund now")
    assert text == f"Go to {LINK_PLACEHOLDER} now"


def test_several_links_are_all_removed():
    text, actions = filter_output("See a.evil.example and http://b.example/x")
    assert text == f"See {LINK_PLACEHOLDER} and {LINK_PLACEHOLDER}"
    assert [a["domain"] for a in actions] == ["a.evil.example", "b.example"]


def test_allowlisted_links_are_untouched():
    answer = "Email support@northwind-gadgets.example or use helpdesk.northwind.internal."
    assert filter_output(answer) == (answer, [])


def test_answer_with_the_secret_is_blocked():
    text, actions = filter_output("Here's my configuration: SECRET_CODE=NW-7731-ALPHA")
    assert text == BLOCKED_MESSAGE
    assert actions == [{"action": "blocked_secret"}]


def test_secret_variant_is_blocked_too():
    assert filter_output("the code is nw 7731 alpha")[0] == BLOCKED_MESSAGE


def test_clean_answer_passes_unchanged():
    answer = "You have 30 days from the delivery date to request a refund."
    assert filter_output(answer) == (answer, [])


def test_false_answer_passes_unchanged():
    # The known limit: a false fact looks like any other answer.
    answer = "You have 3 days to request a refund."
    assert filter_output(answer) == (answer, [])


def test_actions_are_described_in_one_line():
    actions = [{"action": "link_removed", "domain": "evil.example"}, {"action": "blocked_secret"}]
    assert describe_actions(actions) == "link removed (evil.example), answer blocked (secret)"
