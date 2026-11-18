"""Rendering of docs/results.md; no emulator needed."""

from pathlib import PurePosixPath

from sentinel_detections.report import ResultRow, render_results

ROW = ResultRow(
    name="LSASS memory read access",
    rule_path=PurePosixPath("rules/credential_access/lsass_memory_access.yaml"),
    techniques=("T1003.001",),
    attack_dataset="empire_mimikatz_logonpasswords",
    attack_hits=1,
    cross_hits=4,
    fp_baseline=153,
    fp_tuned=0,
)


def test_header_defines_every_count():
    text = render_results([], PurePosixPath("docs"))
    for term in ("**Attack hits**", "**Cross-hits**", "**False positives (FP)**"):
        assert term in text


def test_table_row_links_to_the_rule_relative_to_the_output_folder():
    lines = render_results([ROW], PurePosixPath("docs")).splitlines()
    assert lines[-3:] == [
        "| Rule | Technique | Attack dataset | Attack hits | Cross-hits | FP baseline | FP tuned |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: |",
        "| [LSASS memory read access](../rules/credential_access/lsass_memory_access.yaml) "
        "| T1003.001 | `empire_mimikatz_logonpasswords` | 1 | 4 | 153 | 0 |",
    ]


def test_output_ends_with_a_single_newline():
    text = render_results([ROW], PurePosixPath("docs"))
    assert text.endswith("|\n") and not text.endswith("\n\n")
