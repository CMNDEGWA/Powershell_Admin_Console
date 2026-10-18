from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    KeepTogether,
    LongTable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    TableStyle,
)


def _text(value: Any) -> str:
    if value is None or value == "":
        return "Not available"
    text = "".join(char for char in str(value) if char in "\n\t" or ord(char) >= 32)
    return escape(text).replace("\n", "<br/>")


def _register_unicode_font() -> tuple[str, str]:
    candidates = (
        (
            Path("C:/Windows/Fonts/arial.ttf"),
            Path("C:/Windows/Fonts/arialbd.ttf"),
        ),
        (
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        ),
    )
    for regular, bold in candidates:
        if regular.is_file() and bold.is_file():
            if "PACUnicode" not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont("PACUnicode", str(regular)))
                pdfmetrics.registerFont(TTFont("PACUnicode-Bold", str(bold)))
                pdfmetrics.registerFontFamily(
                    "PACUnicode",
                    normal="PACUnicode",
                    bold="PACUnicode-Bold",
                    italic="PACUnicode",
                    boldItalic="PACUnicode-Bold",
                )
            return "PACUnicode", "PACUnicode-Bold"
    return "Helvetica", "Helvetica-Bold"


def _section_title(text: str, styles: Any) -> Paragraph:
    return Paragraph(escape(text), styles["Heading2"])


def _table_cell(value: Any) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    return _text(value)


def _append_table(
    story: list[Any],
    title: str,
    headers: list[str],
    rows: list[list[Any]],
    styles: Any,
    column_widths: list[Any] | None = None,
) -> None:
    story.extend([Spacer(1, 4 * mm), _section_title(title, styles)])
    if not rows:
        story.append(Paragraph("No records were returned.", styles["BodyText"]))
        return

    data = [[Paragraph(_table_cell(cell), styles["PACHeader"]) for cell in headers]]
    data.extend(
        [Paragraph(_table_cell(cell), styles["PACCell"]) for cell in row]
        for row in rows
    )
    story.append(LongTable(
        data,
        colWidths=column_widths or [176 * mm / len(headers)] * len(headers),
        repeatRows=1,
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17324d")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#b9c4cc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]),
    ))


def build_audit_pdf(audit: dict[str, Any]) -> bytes:
    """Render a saved audit snapshot as a printable PDF summary."""
    snapshot = audit["snapshot"]
    machine = snapshot.get("machine") or {}
    operating_system = machine.get("operatingSystem") or {}
    hardware = machine.get("hardware") or {}
    adapters = machine.get("networkAdapters") or []
    rdp = machine.get("remoteDesktop") or {}

    output = BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=17 * mm,
        leftMargin=17 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"PAC system audit {audit['id']}",
        author="PowerShell Administration Console",
    )
    styles = getSampleStyleSheet()
    regular_font, bold_font = _register_unicode_font()
    for style_name in ("Normal", "Title", "Heading1", "Heading2", "Heading3", "BodyText"):
        styles[style_name].fontName = regular_font
    for style_name in ("Heading1", "Heading2", "Heading3", "Title"):
        styles[style_name].fontName = bold_font
    styles.add(ParagraphStyle(
        name="PACSubTitle",
        parent=styles["Normal"],
        fontName=regular_font,
        textColor=colors.HexColor("#52616b"),
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="PACCenterTitle",
        parent=styles["Title"],
        fontName=bold_font,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#17324d"),
    ))
    styles.add(ParagraphStyle(
        name="PACCell",
        parent=styles["BodyText"],
        fontName=regular_font,
        fontSize=8,
        leading=10,
        wordWrap="CJK",
    ))
    styles.add(ParagraphStyle(
        name="PACFinding",
        parent=styles["BodyText"],
        fontName=regular_font,
        fontSize=9,
        leading=12,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="PACHeader",
        parent=styles["PACCell"],
        fontName=bold_font,
        textColor=colors.white,
    ))

    story: list[Any] = [
        Paragraph("System Audit Report", styles["PACCenterTitle"]),
        Paragraph(
            f"Audit #{audit['id']} · {_text(audit['status'])} · "
            f"Collected {_text(snapshot.get('collected_at'))}",
            styles["PACSubTitle"],
        ),
        _section_title("Machine overview", styles),
    ]
    overview = [
        ["Hostname", _text(machine.get("hostname")), "Windows", _text(operating_system.get("caption"))],
        ["Version / build", _text(f"{operating_system.get('version', '')} / {operating_system.get('build', '')}"),
         "Architecture", _text(operating_system.get("architecture"))],
        ["Manufacturer / model", _text(f"{hardware.get('manufacturer', '')} / {hardware.get('model', '')}"),
         "Administrator", _text(machine.get("administrator"))],
        ["PowerShell", _text(operating_system.get("powershellVersion")),
         "64-bit process", _text(operating_system.get("powershellProcess64Bit"))],
        ["Last boot", _text(operating_system.get("lastBootTime")),
         "Memory", _text(f"{hardware.get('memoryBytes', 'Not available')} bytes")],
    ]
    story.append(LongTable(
        [[Paragraph(_text(cell), styles["PACCell"]) for cell in row] for row in overview],
        colWidths=[35 * mm, 55 * mm, 30 * mm, 55 * mm],
        style=TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8eef2")),
            ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#e8eef2")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#b9c4cc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]),
    ))

    story.extend([Spacer(1, 5 * mm), _section_title("Network adapters", styles)])
    adapter_rows = [["Adapter", "State", "MAC address", "IP addresses"]]
    for adapter in adapters:
        addresses = adapter.get("addresses") or []
        address_text = ", ".join(item.get("address", "") for item in addresses)
        adapter_rows.append([
            adapter.get("name", ""),
            adapter.get("status", ""),
            adapter.get("macAddress", ""),
            address_text,
        ])
    story.append(LongTable(
        [[Paragraph(_text(cell), styles["PACCell"]) for cell in row] for row in adapter_rows],
        colWidths=[40 * mm, 25 * mm, 38 * mm, 72 * mm],
        repeatRows=1,
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17324d")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#b9c4cc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]),
    ))

    accounts = snapshot.get("collectors", {}).get("accountsAndGroups", {}).get("data") or {}
    users = accounts.get("users") or []
    _append_table(
        story,
        "Local accounts",
        ["Account", "Enabled", "Last logon", "Password required", "Source"],
        [[user.get("Name"), user.get("Enabled"), user.get("LastLogon"),
          user.get("PasswordRequired"), user.get("PrincipalSource")] for user in users],
        styles,
    )
    groups = accounts.get("groups") or []
    _append_table(
        story,
        "Local groups and membership",
        ["Group", "Description", "Members"],
        [[group.get("name"), group.get("description"),
          ", ".join(member.get("name") or member.get("errorCode", "")
                    for member in group.get("members", []))]
         for group in groups],
        styles,
    )

    services = snapshot.get("collectors", {}).get("services", {}).get("data") or []
    _append_table(
        story,
        "Services",
        ["Name", "State", "Startup", "Service account", "Executable path"],
        [[service.get("DisplayName"), service.get("State"), service.get("StartMode"),
          service.get("StartName"), service.get("PathName")] for service in services],
        styles,
    )

    software = snapshot.get("collectors", {}).get("installedSoftware", {}).get("data") or []
    _append_table(
        story,
        "Installed software",
        ["Name", "Version", "Publisher", "Install date", "Scope"],
        [[item.get("name"), item.get("version"), item.get("publisher"),
          item.get("installDate"), item.get("scope")] for item in software],
        styles,
    )

    updates = snapshot.get("collectors", {}).get("updates", {}).get("data") or {}
    for key, title, headers, fields in (
        ("installedHotfixes", "Installed hotfixes", ["ID", "Description", "Installed by", "Installed on"],
         ["HotFixID", "Description", "InstalledBy", "InstalledOn"]),
        ("updateHistory", "Windows Update history", ["Date", "Title", "Operation", "Result", "Code"],
         ["Date", "Title", "Operation", "ResultCode", "HResult"]),
        ("pendingUpdates", "Pending updates", ["Title", "Downloaded"], ["title", "downloaded"]),
    ):
        _append_table(
            story,
            title,
            headers,
            [[item.get(field) for field in fields] for item in updates.get(key, [])],
            styles,
        )

    firewall = snapshot.get("collectors", {}).get("firewall", {}).get("data") or {}
    profiles = firewall.get("profiles") or []
    _append_table(
        story,
        "Firewall profiles",
        ["Profile", "Enabled", "Inbound default", "Outbound default", "Notify"],
        [[profile.get("Name"), profile.get("Enabled"), profile.get("DefaultInboundAction"),
          profile.get("DefaultOutboundAction"), profile.get("NotifyOnListen")] for profile in profiles],
        styles,
    )
    rules = firewall.get("rules") or []
    _append_table(
        story,
        "Firewall rules",
        ["Name", "Enabled", "Direction", "Action", "Profile", "Protocol", "Local port",
         "Remote port", "Local address", "Remote address", "Program / service"],
        [[rule.get("DisplayName") or rule.get("Name"), rule.get("Enabled"), rule.get("Direction"),
          rule.get("Action"), rule.get("Profile"), rule.get("Protocol"), rule.get("LocalPort"),
          rule.get("RemotePort"), rule.get("LocalAddress"), rule.get("RemoteAddress"),
          f"{rule.get('Program') or ''} {rule.get('Service') or ''}".strip()] for rule in rules],
        styles,
        column_widths=[width * mm for width in [27, 10, 12, 13, 15, 13, 16, 16, 14, 14, 26]],
    )

    security = snapshot.get("collectors", {}).get("security", {}).get("data") or {}
    _append_table(
        story,
        "Security settings",
        ["Setting", "Collected value"],
        [[key, value] for key, value in security.items()],
        styles,
    )

    scheduled_tasks = snapshot.get("collectors", {}).get("scheduledTasks", {}).get("data") or []
    _append_table(
        story,
        "Scheduled tasks",
        ["Task", "State", "Principal", "Run level", "Actions"],
        [[f"{task.get('taskPath', '')}{task.get('taskName', '')}", task.get("state"),
          task.get("principal"), task.get("runLevel"), task.get("actions")] for task in scheduled_tasks],
        styles,
    )

    event_logs = snapshot.get("collectors", {}).get("eventLogs", {}).get("data") or []
    _append_table(
        story,
        "Event-log coverage",
        ["Channel", "Status", "Enabled", "Records", "Included", "Truncated"],
        [[log.get("channel"), log.get("status"), log.get("enabled"), log.get("recordCount"),
          log.get("collectedCount"), log.get("truncated")] for log in event_logs],
        styles,
    )
    notable_events = []
    for log in event_logs:
        selected = [
            event for event in log.get("events", [])
            if str(event.get("level", "")).lower() in {"critical", "error", "warning"}
        ][:20]
        notable_events.extend([
            [log.get("channel"), event.get("timeCreated"), event.get("eventId"),
             event.get("level"), event.get("provider"), event.get("message")]
            for event in selected
        ])
    _append_table(
        story,
        "Recent warning and error events",
        ["Channel", "Time", "Event ID", "Level", "Provider", "Message"],
        notable_events,
        styles,
        column_widths=[width * mm for width in [20, 25, 12, 14, 20, 85]],
    )

    rdp_enabled_rules = sum(
        1 for rule in rdp.get("firewallRules", [])
        if rule.get("enabled") == "True" and rule.get("direction") == "Inbound"
    )
    story.extend([
        Spacer(1, 5 * mm),
        _section_title("Remote Desktop", styles),
        Paragraph(
            "Configuration: " + _text(rdp.get("configuredEnabled")) +
            " · Service: " + _text(rdp.get("serviceState")) +
            " · Enabled inbound firewall rules: " + str(rdp_enabled_rules),
            styles["BodyText"],
        ),
        Spacer(1, 5 * mm),
        _section_title("Collection coverage", styles),
    ])
    coverage_rows = [["Collector", "Status", "Details"]]
    for name, result in snapshot.get("collectors", {}).items():
        details = result.get("errorCode") or "Collected"
        data = result.get("data")
        if name == "eventLogs" and isinstance(data, list):
            failed_logs = sum(1 for log in data if log.get("status") != "succeeded")
            truncated_logs = sum(1 for log in data if log.get("truncated"))
            details = f"{len(data)} channels; {failed_logs} unavailable; {truncated_logs} truncated"
        coverage_rows.append([name, result.get("status", "unknown"), details])
    story.append(LongTable(
        [[Paragraph(_text(cell), styles["PACCell"]) for cell in row] for row in coverage_rows],
        colWidths=[55 * mm, 30 * mm, 90 * mm],
        repeatRows=1,
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17324d")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#b9c4cc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]),
    ))

    story.extend([Spacer(1, 5 * mm), _section_title("Findings and recommendations", styles)])
    findings = snapshot.get("recommendations", [])
    if not findings:
        story.append(Paragraph("No findings were generated by the configured rules.", styles["BodyText"]))
    else:
        for finding in findings:
            story.append(KeepTogether([
                Paragraph(
                    f"<b>{_text(finding.get('severity', '').upper())}: "
                    f"{_text(finding.get('title'))}</b>",
                    styles["PACFinding"],
                ),
                Paragraph(_text(finding.get("summary")), styles["PACFinding"]),
                Paragraph("Recommendation: " + _text(finding.get("recommendation")), styles["PACFinding"]),
                Paragraph("Evidence: " + _text(finding.get("evidence")), styles["PACCell"]),
                Spacer(1, 3 * mm),
            ]))

    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph(
        "This report contains sensitive system and network information. "
        "Treat it as confidential and retain it only as long as needed.",
        styles["PACSubTitle"],
    ))
    document.build(story)
    return output.getvalue()