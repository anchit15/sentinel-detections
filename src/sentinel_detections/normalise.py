"""Normalise raw OTRF Windows event records into Sentinel-shaped table rows.

Security log events become ``SecurityEvent`` rows: fields that Sentinel exposes as
columns are copied into typed columns, and every event field is also kept in the
``EventData`` XML, as Sentinel does. Sysmon, System and PowerShell Operational
events become generic ``Event`` rows whose fields live only in ``EventData`` XML.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache
from importlib import resources
from xml.sax.saxutils import escape, quoteattr

SECURITY_EVENT = "SecurityEvent"
EVENT = "Event"
DATASET_COLUMN = "Dataset"

# Lower-cased channel -> (target table, channel name as Windows spells it).
# Some OTRF records spell the Security channel in lower case.
CHANNEL_ROUTES: dict[str, tuple[str, str]] = {
    "security": (SECURITY_EVENT, "Security"),
    "system": (EVENT, "System"),
    "microsoft-windows-sysmon/operational": (EVENT, "Microsoft-Windows-Sysmon/Operational"),
    "microsoft-windows-powershell/operational": (
        EVENT,
        "Microsoft-Windows-PowerShell/Operational",
    ),
}

# Fields added by the log shipper or taken from the event's System header.
# They are not event data, so they never go into EventData.
ENVELOPE_FIELDS = frozenset(
    {
        "@timestamp",
        "@version",
        "AccountName",
        "AccountType",
        "ActivityID",
        "Category",
        "Channel",
        "Domain",
        "ERROR_EVT_UNRESOLVED",
        "EventID",
        "EventReceivedTime",
        "EventTime",
        "ExecutionProcessID",
        "Hostname",
        "Keywords",
        "Level",
        "Message",
        "Opcode",
        "OpcodeValue",
        "ProviderGuid",
        "RecordNumber",
        "Severity",
        "SeverityValue",
        "SourceModuleName",
        "SourceModuleType",
        "SourceName",
        "Task",
        "ThreadID",
        "TimeCreated",
        "UserID",
        "Version",
        "host",
        "port",
        "tags",
    }
)

EVENT_XML_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"

# NXLog severity (1 debug .. 5 critical) -> Windows event level (5 verbose .. 1 critical).
NXLOG_SEVERITY_TO_LEVEL = {1: 5, 2: 4, 3: 3, 4: 2, 5: 1}
LEVEL_NAMES = {
    0: "Information",
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Information",
    5: "Verbose",
}

# Characters that XML 1.0 does not allow, even when escaped.
INVALID_XML_CHARS = re.compile("[^\t\n\r\x20-퟿-�\U00010000-\U0010ffff]")

SCHEMA_FILES = {SECURITY_EVENT: "security_event.json", EVENT: "event.json"}

# Time zone offsets are whole multiples of 15 minutes.
OFFSET_GRANULARITY = timedelta(minutes=15)


class NormalisationError(ValueError):
    """Raised when a record cannot be turned into a table row.

    ``reason`` is a short, stable label used to count dropped records.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass(frozen=True)
class TableSchema:
    """Column names and Kusto types of one Sentinel table, in schema order."""

    table: str
    columns: tuple[tuple[str, str], ...]

    @property
    def types(self) -> dict[str, str]:
        """Map each column name to its Kusto type."""
        return dict(self.columns)

    @property
    def output_columns(self) -> tuple[tuple[str, str], ...]:
        """Sentinel columns plus the Dataset tag column used for per-dataset tests."""
        return (*self.columns, (DATASET_COLUMN, "string"))


@dataclass(frozen=True)
class NormalisedRow:
    """A row destined for ``table``; ``values`` holds only the populated columns."""

    table: str
    values: dict[str, object]


@cache
def load_schema(table: str) -> TableSchema:
    """Load a Sentinel table schema bundled under ``sentinel_detections/schemas``."""
    path = resources.files("sentinel_detections") / "schemas" / SCHEMA_FILES[table]
    document = json.loads(path.read_text(encoding="utf-8"))
    columns = tuple((column["name"], column["type"]) for column in document["columns"])
    return TableSchema(table=document["table"], columns=columns)


def route(record: Mapping[str, object]) -> tuple[str, str] | None:
    """Return (table, canonical channel) for a record, or None if its channel is not loaded."""
    return CHANNEL_ROUTES.get(str(record.get("Channel", "")).lower())


def normalise(
    record: Mapping[str, object],
    dataset_id: str,
    naive_offset: timedelta | None = None,
) -> NormalisedRow | None:
    """Turn one raw record into a table row.

    ``naive_offset`` converts a ``TimeCreated`` without a time zone to UTC; see
    ``naive_time_offset``. Returns None when the record's channel is not loaded into
    either table. Raises NormalisationError when required fields are missing or invalid.
    """
    destination = route(record)
    if destination is None:
        return None
    table, channel = destination
    time_generated = _time_generated(record, naive_offset)
    if table == SECURITY_EVENT:
        values = _security_event_values(record, channel, time_generated)
    else:
        values = _event_values(record, channel, time_generated)
    values[DATASET_COLUMN] = dataset_id
    return NormalisedRow(table=table, values=values)


def naive_time_offset(records: Iterable[Mapping[str, object]]) -> timedelta | None:
    """Learn the offset that turns a dataset's zone-less ``TimeCreated`` into UTC.

    Some OTRF exports wrote ``TimeCreated`` as local time on a 12-hour clock without
    AM/PM. Sysmon's ``UtcTime`` is always UTC, so records carrying both reveal the
    offset, which is then applied to the dataset's records that only have
    ``TimeCreated``. Returns None if no record has both fields.
    Raises ValueError if the records disagree, for example when a capture crosses
    noon and the missing AM/PM flips the offset.
    """
    offsets = set()
    for record in records:
        if record.get("@timestamp"):
            continue
        created = _parse_naive(record.get("TimeCreated"))
        utc_time = _parse_naive(record.get("UtcTime"))
        if created is None or utc_time is None:
            continue
        steps = round((utc_time - created) / OFFSET_GRANULARITY)
        offsets.add(steps * OFFSET_GRANULARITY)
    if len(offsets) > 1:
        raise ValueError(f"Inconsistent TimeCreated offsets: {sorted(offsets)}")
    return offsets.pop() if offsets else None


def event_data_fields(record: Mapping[str, object]) -> list[tuple[str, str]]:
    """Return the event's own fields as (name, text) pairs, in source order."""
    # NXLog adds its own EventType (INFO, AUDIT_SUCCESS). When an event also has an
    # EventType data field (Sysmon registry events), OTRF's pipeline kept the data
    # value in EventType and moved NXLog's value to the misspelt EventTypeOrignal.
    nxlog_event_type = "EventTypeOrignal" not in record and "SourceModuleName" in record
    fields = []
    for name, value in record.items():
        if name in ENVELOPE_FIELDS or name == "EventTypeOrignal":
            continue
        if name == "EventType" and nxlog_event_type:
            continue
        fields.append((name, to_text(value)))
    return fields


def build_event_data_xml(fields: Iterable[tuple[str, str]]) -> str:
    """Serialise fields as a Windows ``<EventData>`` element."""
    items = "".join(
        f"<Data Name={quoteattr(_xml_safe(name))}>{escape(_xml_safe(value))}</Data>"
        for name, value in fields
    )
    return f'<EventData xmlns="{EVENT_XML_NAMESPACE}">{items}</EventData>'


def to_text(value: object) -> str:
    """Render a raw JSON value as the text Windows would log."""
    if value is None:
        return ""
    if isinstance(value, dict | list):
        return json.dumps(value)
    return str(value)


def cast(value: object, kusto_type: str) -> object:
    """Convert a raw value to a column's Kusto type; None if it does not fit."""
    if kusto_type == "int":
        return _to_int(value)
    text = to_text(value)
    return text or None


def account_name(domain: object, user: object) -> str | None:
    """Combine domain and user as ``DOMAIN\\user``, the format Sentinel uses."""
    user_text = to_text(user)
    if user_text in ("", "-"):
        return None
    domain_text = to_text(domain)
    return f"{domain_text}\\{user_text}" if domain_text not in ("", "-") else user_text


def _security_event_values(
    record: Mapping[str, object], channel: str, time_generated: str
) -> dict[str, object]:
    types = load_schema(SECURITY_EVENT).types
    fields = event_data_fields(record)
    event_id = _event_id(record)
    subject = account_name(record.get("SubjectDomainName"), record.get("SubjectUserName"))
    target = account_name(record.get("TargetDomainName"), record.get("TargetUserName"))
    account = target or subject
    message = to_text(record.get("Message")).strip()
    activity = f"{event_id} - {message.splitlines()[0].strip()}" if message else str(event_id)

    # Values that Sentinel's agent fills from the event header or derives itself.
    # They take precedence over same-named event fields such as Type.
    derived: dict[str, object] = {
        "TimeGenerated": time_generated,
        "Computer": _computer(record),
        "EventID": event_id,
        "Channel": channel,
        "EventSourceName": cast(record.get("SourceName"), "string"),
        "Task": _to_int(record.get("Task")),
        "Version": _to_int(record.get("Version")),
        "Level": cast(_windows_level(record), "string"),
        "Keywords": _keywords_hex(record.get("Keywords")),
        "Opcode": cast(record.get("Opcode"), "string"),
        "EventRecordId": cast(record.get("RecordNumber"), "string"),
        "Activity": activity,
        "Account": account,
        "AccountType": _account_type(account),
        "SubjectAccount": subject,
        "TargetAccount": target,
        "EventData": build_event_data_xml(fields),
        "Type": SECURITY_EVENT,
    }
    values: dict[str, object] = {}
    for name, text in fields:
        if name in types and name not in derived:
            converted = cast(text, types[name])
            if converted is not None:
                values[name] = converted
    values.update({name: value for name, value in derived.items() if value is not None})
    return values


def _event_values(
    record: Mapping[str, object], channel: str, time_generated: str
) -> dict[str, object]:
    level = _windows_level(record)
    event_data = build_event_data_xml(event_data_fields(record))
    values: dict[str, object | None] = {
        "TimeGenerated": time_generated,
        "Computer": _computer(record),
        "EventLog": channel,
        "Source": cast(record.get("SourceName"), "string"),
        "EventID": _event_id(record),
        "EventLevel": level,
        "EventLevelName": LEVEL_NAMES.get(level) if level is not None else None,
        "EventCategory": _to_int(record.get("Task")),
        "UserName": account_name(record.get("Domain"), record.get("AccountName")),
        "RenderedDescription": cast(record.get("Message"), "string"),
        # Sentinel wraps Event.EventData in a DataItem element.
        "EventData": (
            f'<DataItem type="System.XPath.Navigation" time="{time_generated}">'
            f"{event_data}</DataItem>"
        ),
        "Type": EVENT,
    }
    return {name: value for name, value in values.items() if value is not None}


def _event_id(record: Mapping[str, object]) -> int:
    if record.get("EventID") in (None, ""):
        raise NormalisationError("missing EventID")
    event_id = _to_int(record["EventID"])
    if event_id is None:
        raise NormalisationError("invalid EventID", repr(record["EventID"]))
    return event_id


def _computer(record: Mapping[str, object]) -> str:
    hostname = to_text(record.get("Hostname")).strip()
    if not hostname:
        raise NormalisationError("missing Hostname")
    return hostname


def _time_generated(record: Mapping[str, object], naive_offset: timedelta | None) -> str:
    """Return the event time as UTC ISO 8601.

    ``@timestamp`` is UTC. ``TimeCreated`` is used when it is the only time field:
    as-is when it carries a time zone, shifted by ``naive_offset`` when it does not.
    NXLog's ``EventTime`` is local time, so it is never used.
    """
    raw = record.get("@timestamp") or record.get("TimeCreated")
    if not raw:
        raise NormalisationError("missing timestamp")
    try:
        parsed = datetime.fromisoformat(str(raw))
    except ValueError as error:
        raise NormalisationError("invalid timestamp", repr(raw)) from error
    if parsed.tzinfo is None:
        if naive_offset is None:
            raise NormalisationError("timestamp without time zone", repr(raw))
        parsed = (parsed + naive_offset).replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_naive(value: object) -> datetime | None:
    """Parse a timestamp that has no time zone; None if absent, invalid or zoned."""
    try:
        parsed = datetime.fromisoformat(to_text(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is None else None


def _windows_level(record: Mapping[str, object]) -> int | None:
    level = _to_int(record.get("Level"))
    if level is not None:
        return level
    severity = _to_int(record.get("SeverityValue"))
    return NXLOG_SEVERITY_TO_LEVEL.get(severity) if severity is not None else None


def _keywords_hex(value: object) -> str | None:
    """Render keywords as hex; NXLog stores the 64-bit mask as a signed integer."""
    if isinstance(value, int):
        return f"0x{value % 2**64:x}"
    return cast(value, "string")


def _account_type(account: str | None) -> str | None:
    if account is None:
        return None
    return "Machine" if account.endswith("$") else "User"


def _to_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = to_text(value).strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _xml_safe(text: str) -> str:
    return INVALID_XML_CHARS.sub("", text)
