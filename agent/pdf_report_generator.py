
import json
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether
)


# ==================================================
# PROJECT CONFIGURATION
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

REPORT_DIR = PROJECT_ROOT / "reports"

INPUT_FILE = REPORT_DIR / "central_alert_report.json"

OUTPUT_FILE = REPORT_DIR / "security_assessment_report.pdf"


# ==================================================
# REPORT CONFIGURATION
# ==================================================

PAGE_WIDTH, PAGE_HEIGHT = A4

NAVY = colors.HexColor("#14213D")
BLUE = colors.HexColor("#2563EB")
LIGHT_BLUE = colors.HexColor("#EAF1FF")
LIGHT_GREY = colors.HexColor("#F1F5F9")
DARK_GREY = colors.HexColor("#334155")


# ==================================================
# PDF STYLES
# ==================================================

styles = getSampleStyleSheet()

styles.add(ParagraphStyle(
    name="ReportTitle",
    parent=styles["Title"],
    fontSize=23,
    leading=30,
    textColor=NAVY,
    alignment=TA_CENTER,
    spaceAfter=12
))

styles.add(ParagraphStyle(
    name="SectionHeading",
    parent=styles["Heading2"],
    fontSize=13,
    leading=18,
    textColor=BLUE,
    spaceBefore=14,
    spaceAfter=8
))

styles.add(ParagraphStyle(
    name="SmallText",
    parent=styles["BodyText"],
    fontSize=8,
    leading=11,
    textColor=DARK_GREY
))

styles.add(ParagraphStyle(
    name="TableText",
    parent=styles["BodyText"],
    fontSize=7,
    leading=9,
    wordWrap="CJK"
))


# ==================================================
# JSON PROCESSING
# ==================================================

def load_report():

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input report not found: {INPUT_FILE}"
        )

    with INPUT_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def flatten_json(data, parent=""):

    rows = []

    if isinstance(data, dict):

        for key, value in data.items():

            path = f"{parent}.{key}" if parent else key

            if isinstance(value, (dict, list)):
                rows.extend(flatten_json(value, path))

            else:
                rows.append((path, value))

    elif isinstance(data, list):

        if not data:
            rows.append((parent, "No records"))

        for index, item in enumerate(data):

            path = f"{parent}[{index}]"

            if isinstance(item, (dict, list)):
                rows.extend(flatten_json(item, path))

            else:
                rows.append((path, item))

    else:
        rows.append((parent, data))

    return rows


def collect_statistics(data):

    statistics = {
        "total_findings": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "critical": 0,
        "review_required": 0
    }

    def walk(obj):

        if isinstance(obj, dict):

            severity = str(
                obj.get("severity", "")
            ).lower()

            if severity in (
                "critical", "high", "medium", "low"
            ):
                statistics[severity] += 1
                statistics["total_findings"] += 1

            if str(obj.get("risk_status", "")).upper() == "REVIEW_REQUIRED":
                statistics["review_required"] += 1

            for value in obj.values():
                walk(value)

        elif isinstance(obj, list):

            for item in obj:
                walk(item)

    walk(data)

    return statistics


# ==================================================
# TABLE GENERATOR
# ==================================================

def create_data_table(rows):

    table_data = [[
        Paragraph("<b>FIELD</b>", styles["TableText"]),
        Paragraph("<b>VALUE</b>", styles["TableText"])
    ]]

    for key, value in rows:

        value = str(value)

        table_data.append([
            Paragraph(escape(str(key)), styles["TableText"]),
            Paragraph(escape(value), styles["TableText"])
        ])

    table = Table(
        table_data,
        colWidths=[65 * mm, 105 * mm],
        repeatRows=1,
        hAlign="LEFT"
    )

    table.setStyle(TableStyle([

        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),

        ("BACKGROUND", (0, 1), (-1, -1), colors.white),

        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, LIGHT_GREY]),

        ("VALIGN", (0, 0), (-1, -1), "TOP"),

        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5)

    ]))

    return table


# ==================================================
# PAGE HEADER & FOOTER
# ==================================================

def add_page_elements(canvas, document):

    canvas.saveState()

    canvas.setStrokeColor(BLUE)
    canvas.setLineWidth(1)

    canvas.line(
        20 * mm,
        PAGE_HEIGHT - 15 * mm,
        PAGE_WIDTH - 20 * mm,
        PAGE_HEIGHT - 15 * mm
    )

    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(DARK_GREY)

    canvas.drawString(
        20 * mm,
        10 * mm,
        "Windows Monitoring Agent | Security Assessment"
    )

    canvas.drawRightString(
        PAGE_WIDTH - 20 * mm,
        10 * mm,
        f"Page {document.page}"
    )

    canvas.restoreState()


# ==================================================
# PDF REPORT GENERATOR
# ==================================================

def generate_pdf():

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading central security report...")

    data = load_report()

    print("Analyzing security findings...")

    statistics = collect_statistics(data)

    document = SimpleDocTemplate(
        str(OUTPUT_FILE),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=23 * mm,
        bottomMargin=20 * mm,
        title="Windows Security Assessment Report",
        author="Windows Monitoring Agent"
    )

    story = []

    # TITLE

    story.append(Spacer(1, 20 * mm))

    story.append(Paragraph(
        "WINDOWS SECURITY<br/>ASSESSMENT REPORT",
        styles["ReportTitle"]
    ))

    story.append(Paragraph(
        "Process & Service Monitoring Analysis",
        styles["Heading3"]
    ))

    story.append(Spacer(1, 15 * mm))

    metadata = [
        ("Report Generated", datetime.now().astimezone().isoformat()),
        ("Source File", INPUT_FILE.name),
        ("Platform", "Microsoft Windows"),
        ("Report Format", "PDF"),
        ("Monitoring Agent", "Windows Monitoring Agent")
    ]

    story.append(create_data_table(metadata))

    story.append(Spacer(1, 15 * mm))

    # EXECUTIVE SUMMARY

    story.append(Paragraph(
        "1. EXECUTIVE SUMMARY",
        styles["SectionHeading"]
    ))

    summary = [
        ("Total Severity Findings", statistics["total_findings"]),
        ("Critical Findings", statistics["critical"]),
        ("High Findings", statistics["high"]),
        ("Medium Findings", statistics["medium"]),
        ("Low Findings", statistics["low"]),
        ("Processes Requiring Review",
         statistics["review_required"])
    ]

    story.append(create_data_table(summary))

    story.append(Spacer(1, 10 * mm))

    # DETAILED SECURITY DATA

    story.append(Paragraph(
        "2. DETAILED SECURITY ASSESSMENT",
        styles["SectionHeading"]
    ))

    story.append(Paragraph(
        "The following section contains the complete "
        "available information extracted from the central "
        "security JSON report.",
        styles["SmallText"]
    ))

    story.append(Spacer(1, 5 * mm))

    all_rows = flatten_json(data)

    CHUNK_SIZE = 35

    for start in range(0, len(all_rows), CHUNK_SIZE):

        chunk = all_rows[start:start + CHUNK_SIZE]

        story.append(create_data_table(chunk))
        story.append(Spacer(1, 6 * mm))

    # RECOMMENDATIONS

    story.append(Paragraph(
        "3. SECURITY RECOMMENDATIONS",
        styles["SectionHeading"]
    ))

    recommendations = [
        "Investigate all HIGH and CRITICAL findings.",
        "Verify unknown processes using their executable "
        "paths and digital signatures.",
        "Review suspicious service configurations.",
        "Investigate repeated CPU and memory threshold alerts.",
        "Validate findings before taking remediation actions.",
        "Maintain regular monitoring and update security baselines."
    ]

    for recommendation in recommendations:

        story.append(Paragraph(
            "• " + escape(recommendation),
            styles["BodyText"]
        ))

        story.append(Spacer(1, 4))

    # DISCLAIMER

    story.append(Spacer(1, 10 * mm))

    story.append(Paragraph(
        "DISCLAIMER",
        styles["SectionHeading"]
    ))

    story.append(Paragraph(
        "This report is generated automatically from monitoring "
        "data. Findings require manual verification. An alert "
        "does not necessarily indicate malicious activity.",
        styles["SmallText"]
    ))

    document.build(
        story,
        onFirstPage=add_page_elements,
        onLaterPages=add_page_elements
    )

    print("\n" + "=" * 65)
    print("WINDOWS SECURITY PDF REPORT GENERATOR")
    print("=" * 65)

    print("[SUCCESS] PDF generated successfully!")
    print(f"Report Location: {OUTPUT_FILE}")
    print(f"Total Findings: {statistics['total_findings']}")
    print(f"High: {statistics['high']}")
    print(f"Medium: {statistics['medium']}")
    print(f"Low: {statistics['low']}")
    print(f"Critical: {statistics['critical']}")

    print("=" * 65)


# ==================================================
# MAIN
# ==================================================

if __name__ == "__main__":

    try:
        generate_pdf()

    except Exception as error:
        print(f"\n[ERROR] {error}")
