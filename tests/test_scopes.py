"""Scope matching contract (design §5): Python fnmatch.fnmatchcase, fail closed."""

from custos.scopes import scope_allows


def test_empty_scopes_fail_closed() -> None:
    assert not scope_allows([], "aliyun")
    assert not scope_allows([], "anything")


def test_star_matches_dotted_names() -> None:
    assert scope_allows(["*"], "aliyun")
    assert scope_allows(["*"], "stock-a.b")


def test_prefix_pattern() -> None:
    assert scope_allows(["stock-*"], "stock-a.b")
    assert not scope_allows(["stock-*"], "stocks-a")
    assert not scope_allows(["stock-*"], "xstock-a")


def test_character_class_literal() -> None:
    assert scope_allows(["key[abc]"], "keya")
    assert not scope_allows(["key[abc]"], "keyd")


def test_case_sensitive() -> None:
    assert not scope_allows(["Aliyun"], "aliyun")
    assert scope_allows(["aliyun"], "aliyun")


def test_question_mark_single_char() -> None:
    assert scope_allows(["key?"], "key1")
    assert not scope_allows(["key?"], "key12")
