"""Argument handling for scripts/kql.py; no emulator needed."""

import importlib.util
import io

import pytest

from paths import REPO_ROOT


def load_script():
    spec = importlib.util.spec_from_file_location("kql_cli", REPO_ROOT / "scripts" / "kql.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kql = load_script()


def test_defaults_read_stdin_with_limit_50():
    args = kql.parse_args([])
    assert (args.query_file, args.limit, args.width) == ("-", 50, 60)


def test_file_limit_and_width_are_parsed():
    args = kql.parse_args(["query.kql", "--limit", "5", "--width", "20"])
    assert (args.query_file, args.limit, args.width) == ("query.kql", 5, 20)


@pytest.mark.parametrize("value", ["0", "-3", "ten"])
def test_limit_must_be_a_positive_integer(value):
    with pytest.raises(SystemExit):
        kql.parse_args(["--limit", value])


def test_query_is_read_from_a_file(tmp_path):
    path = tmp_path / "query.kql"
    path.write_text("Event\n| take 5;\n\n", encoding="utf-8")
    assert kql.read_query(str(path), io.StringIO("ignored")) == "Event\n| take 5"


def test_query_is_read_from_stdin():
    stdin = io.StringIO('SecurityEvent | where Dataset == "empire_dcsync"\n')
    assert kql.read_query("-", stdin) == 'SecurityEvent | where Dataset == "empire_dcsync"'


def test_empty_query_is_rejected():
    with pytest.raises(ValueError, match="empty"):
        kql.read_query("-", io.StringIO("  \n;\n"))


def test_missing_file_exits_with_an_error(tmp_path, capsys):
    assert kql.main([str(tmp_path / "missing.kql")]) == 2
    assert "error:" in capsys.readouterr().err
