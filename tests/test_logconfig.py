from vulnavigator.logconfig import configure_logging
from vulnavigator.pipeline import _workers, analyze_text
from vulnavigator.report import to_markdown


def test_configure_logging_is_idempotent():
    configure_logging(level="WARNING", fmt="text")
    configure_logging(level="INFO", fmt="json")


def test_workers_env(monkeypatch):
    monkeypatch.delenv("VULN_NAV_WORKERS", raising=False)
    assert _workers(None, 1) == 1
    assert _workers(None, 10) == 4
    assert _workers(2, 10) == 2
    monkeypatch.setenv("VULN_NAV_WORKERS", "1")
    assert _workers(None, 8) == 1


def test_analyze_many_parallel_preserves_order():
    cases = analyze_text(
        '[{"title":"one","cwe":"CWE-89","description":"sql injection in login"},'
        '{"title":"two","cwe":"CWE-79","description":"reflected xss on search"}]',
        offline=True,
        workers=2,
    )
    assert [c.title for c in cases] == ["one", "two"]
    md = to_markdown(cases[0])
    assert "## 11. Confidence and Assumptions" in md
