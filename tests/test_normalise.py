from datetime import timedelta
from xml.etree import ElementTree

import pytest

from sentinel_detections.normalise import (
    DATASET_COLUMN,
    EVENT,
    EVENT_XML_NAMESPACE,
    SECURITY_EVENT,
    NormalisationError,
    load_schema,
    naive_time_offset,
    normalise,
)

NS = {"e": EVENT_XML_NAMESPACE}


def nxlog_security(**fields):
    """A Security record in the NXLog-shipped shape most OTRF datasets use."""
    record = {
        "@timestamp": "2020-09-21T22:58:30.648Z",
        "@version": "1",
        "host": "wec.internal.cloudapp.net",
        "port": 64545,
        "tags": ["mordorDataset"],
        "SourceModuleName": "eventlog",
        "EventTime": "2020-09-21 18:58:30",
        "EventType": "AUDIT_SUCCESS",
        "Keywords": -9214364837600034816,
        "SeverityValue": 2,
        "Channel": "Security",
        "SourceName": "Microsoft-Windows-Security-Auditing",
        "Hostname": "WORKSTATION5.theshire.local",
        "EventID": 4624,
        "Task": 12544,
        "Version": 2,
        "RecordNumber": 155867,
        "Message": "An account was successfully logged on.\r\n\r\nSubject: ...",
        "SubjectUserName": "WORKSTATION5$",
        "SubjectDomainName": "THESHIRE",
        "TargetUserName": "wardog",
        "TargetDomainName": "WORKSTATION5",
        "LogonType": "9",
        "LogonProcessName": "seclogo",
    }
    record.update(fields)
    return record


def nxlog_sysmon(**fields):
    """A Sysmon registry event in the NXLog-shipped shape."""
    record = {
        "@timestamp": "2020-07-22T04:18:51.000Z",
        "SourceModuleName": "eventlog",
        "EventTime": "2020-07-22 00:18:51",
        "EventType": "SetValue",
        "EventTypeOrignal": "INFO",
        "AccountName": "SYSTEM",
        "Domain": "NT AUTHORITY",
        "UserID": "S-1-5-18",
        "SeverityValue": 2,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "SourceName": "Microsoft-Windows-Sysmon",
        "Hostname": "WORKSTATION5.theshire.local",
        "EventID": 13,
        "Task": 13,
        "Message": "Registry value set:\r\nRuleName: -",
        "RuleName": "-",
        "UtcTime": "2020-07-22 04:18:51.000",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        "Details": "powershell -nop -w hidden",
    }
    record.update(fields)
    return record


def event_data(row, table):
    """Parse a row's EventData XML into {Name: text}."""
    root = ElementTree.fromstring(row.values["EventData"])
    if table == EVENT:
        assert root.tag == "DataItem"
        root = root.find("e:EventData", NS)
    return {data.get("Name"): data.text or "" for data in root.findall("e:Data", NS)}


@pytest.mark.parametrize("channel", ["Security", "security", "SECURITY"])
def test_security_channel_routes_to_security_event_in_any_case(channel):
    row = normalise(nxlog_security(Channel=channel), "ds")
    assert row.table == SECURITY_EVENT
    assert row.values["Channel"] == "Security"


@pytest.mark.parametrize(
    "channel",
    [
        "System",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-PowerShell/Operational",
    ],
)
def test_sysmon_system_and_powershell_route_to_event(channel):
    row = normalise(nxlog_sysmon(Channel=channel), "ds")
    assert row.table == EVENT
    assert row.values["EventLog"] == channel


@pytest.mark.parametrize(
    "channel", ["Windows PowerShell", "Microsoft-Windows-WMI-Activity/Operational", None]
)
def test_other_channels_are_not_loaded(channel):
    assert normalise(nxlog_sysmon(Channel=channel), "ds") is None


def test_schema_columns_are_typed():
    row = normalise(nxlog_security(), "ds")
    assert row.values["LogonType"] == 9
    assert row.values["EventID"] == 4624
    assert row.values["TargetUserName"] == "wardog"
    assert row.values["TimeGenerated"] == "2020-09-21T22:58:30.648000Z"


def test_value_that_does_not_fit_an_int_column_stays_only_in_event_data():
    row = normalise(nxlog_security(LogonType="%%2313"), "ds")
    assert "LogonType" not in row.values
    assert event_data(row, SECURITY_EVENT)["LogonType"] == "%%2313"


def test_field_without_a_column_is_kept_in_event_data():
    row = normalise(nxlog_security(EventID=4769, TicketEncryptionType="0x17"), "ds")
    assert "TicketEncryptionType" not in load_schema(SECURITY_EVENT).types
    assert event_data(row, SECURITY_EVENT)["TicketEncryptionType"] == "0x17"


def test_envelope_fields_are_not_event_data():
    data = event_data(normalise(nxlog_security(), "ds"), SECURITY_EVENT)
    for envelope in (
        "@timestamp",
        "@version",
        "host",
        "port",
        "tags",
        "Hostname",
        "Message",
        "SourceModuleName",
        "EventTime",
        "Keywords",
        "EventType",
        "EventID",
    ):
        assert envelope not in data
    assert data["SubjectUserName"] == "WORKSTATION5$"


def test_event_data_is_valid_xml_with_special_characters_escaped():
    awkward = 'cmd /c "a<b" & echo \x01done'
    row = normalise(nxlog_sysmon(Details=awkward), "ds")
    assert event_data(row, EVENT)["Details"] == 'cmd /c "a<b" & echo done'


def test_event_table_wraps_event_data_in_data_item():
    row = normalise(nxlog_sysmon(), "ds")
    root = ElementTree.fromstring(row.values["EventData"])
    assert root.tag == "DataItem"
    assert root.find("e:EventData", NS) is not None


def test_sysmon_event_type_keeps_the_data_value_not_the_shipper_value():
    data = event_data(normalise(nxlog_sysmon(), "ds"), EVENT)
    assert data["EventType"] == "SetValue"
    assert "EventTypeOrignal" not in data


def test_shipper_event_type_without_original_is_dropped():
    record = nxlog_sysmon(EventType="INFO")
    del record["EventTypeOrignal"]
    assert "EventType" not in event_data(normalise(record, "ds"), EVENT)


def test_event_type_is_data_when_record_was_not_shipped_by_nxlog():
    record = nxlog_sysmon()
    for key in ("SourceModuleName", "EventTypeOrignal"):
        del record[key]
    assert event_data(normalise(record, "ds"), EVENT)["EventType"] == "SetValue"


def test_event_row_header_columns():
    row = normalise(nxlog_sysmon(), "ds")
    assert row.values["Source"] == "Microsoft-Windows-Sysmon"
    assert row.values["UserName"] == "NT AUTHORITY\\SYSTEM"
    assert row.values["EventLevel"] == 4
    assert row.values["EventLevelName"] == "Information"
    assert row.values["Type"] == EVENT


def test_derived_security_event_columns():
    row = normalise(nxlog_security(), "ds")
    assert row.values["Account"] == "WORKSTATION5\\wardog"
    assert row.values["SubjectAccount"] == "THESHIRE\\WORKSTATION5$"
    assert row.values["AccountType"] == "User"
    assert row.values["Activity"] == "4624 - An account was successfully logged on."
    assert row.values["Keywords"] == "0x8020000000000000"
    assert row.values["Computer"] == "WORKSTATION5.theshire.local"


def test_account_falls_back_to_subject_when_there_is_no_target():
    row = normalise(nxlog_security(EventID=4688, TargetUserName="-", TargetDomainName="-"), "ds")
    assert row.values["Account"] == "THESHIRE\\WORKSTATION5$"
    assert row.values["AccountType"] == "Machine"


def test_event_field_cannot_overwrite_a_derived_column():
    row = normalise(nxlog_security(EventID=5379, Type="5"), "ds")
    assert row.values["Type"] == SECURITY_EVENT
    assert event_data(row, SECURITY_EVENT)["Type"] == "5"


@pytest.mark.parametrize("record", [nxlog_security(), nxlog_sysmon()])
def test_rows_only_use_schema_columns_and_carry_the_dataset_tag(record):
    row = normalise(record, "empire_dcsync")
    allowed = {name for name, _ in load_schema(row.table).output_columns}
    assert set(row.values) <= allowed
    assert row.values[DATASET_COLUMN] == "empire_dcsync"
    assert load_schema(row.table).output_columns[-1] == (DATASET_COLUMN, "string")


def test_zoned_time_created_is_used_when_there_is_no_at_timestamp():
    record = nxlog_security(TimeCreated="2022-08-18T06:55:56.586Z")
    del record["@timestamp"]
    assert normalise(record, "ds").values["TimeGenerated"] == "2022-08-18T06:55:56.586000Z"


def test_naive_time_created_is_shifted_by_the_dataset_offset():
    record = nxlog_security(TimeCreated="2020-10-18 07:50:06.220")
    del record["@timestamp"]
    row = normalise(record, "ds", naive_offset=timedelta(hours=16))
    assert row.values["TimeGenerated"] == "2020-10-18T23:50:06.220000Z"


def test_naive_time_created_without_an_offset_is_rejected():
    record = nxlog_security(TimeCreated="2020-10-18 07:50:06.220")
    del record["@timestamp"]
    with pytest.raises(NormalisationError) as error:
        normalise(record, "ds")
    assert error.value.reason == "timestamp without time zone"


def test_naive_time_offset_is_learned_from_sysmon_utc_time():
    records = [
        {"TimeCreated": "2020-10-18 07:50:05.846", "UtcTime": "2020-10-18 23:50:05.846"},
        {"TimeCreated": "2020-10-18 07:50:07.347", "UtcTime": "2020-10-18 23:50:07.348"},
        {"TimeCreated": "2020-10-18 07:50:08.000"},
        {"@timestamp": "2020-10-18T23:50:00Z", "UtcTime": "2020-10-18 23:50:00.000"},
    ]
    assert naive_time_offset(records) == timedelta(hours=16)


def test_naive_time_offset_is_none_without_evidence():
    assert naive_time_offset([{"@timestamp": "2020-10-18T23:50:00Z"}]) is None


def test_inconsistent_naive_time_offsets_fail_loudly():
    # A capture crossing noon on a 12-hour clock: 11:59 AM, then 1:01 PM logged as 01:01.
    records = [
        {"TimeCreated": "2020-10-18 11:59:00.000", "UtcTime": "2020-10-18 15:59:00.000"},
        {"TimeCreated": "2020-10-18 01:01:00.000", "UtcTime": "2020-10-18 17:01:00.000"},
    ]
    with pytest.raises(ValueError, match="Inconsistent"):
        naive_time_offset(records)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"EventID": None}, "missing EventID"),
        ({"EventID": "abc"}, "invalid EventID"),
        ({"Hostname": ""}, "missing Hostname"),
        ({"@timestamp": None}, "missing timestamp"),
        ({"@timestamp": "yesterday"}, "invalid timestamp"),
    ],
)
def test_invalid_records_raise_with_a_countable_reason(change, reason):
    with pytest.raises(NormalisationError) as error:
        normalise(nxlog_security(**change), "ds")
    assert error.value.reason == reason
