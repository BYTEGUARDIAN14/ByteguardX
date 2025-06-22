from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch


def severity_color(severity):
    if severity.lower() == "critical":
        return colors.red
    elif severity.lower() == "high":
        return colors.orange
    elif severity.lower() == "medium":
        return colors.yellow
    else:
        return colors.green


def generate_pdf_report(results, output_path, project_name="Project", file_count=0, vulnerabilities=None):
    if vulnerabilities is None:
        vulnerabilities = results
    c = canvas.Canvas(output_path, pagesize=letter)
    width, height = letter
    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, height - 50, f"Security Scan Report: {project_name}")
    c.setFont("Helvetica", 12)
    c.drawString(50, height - 80, f"Files Scanned: {file_count}")
    c.drawString(50, height - 100, f"Total Vulnerabilities: {len(vulnerabilities)}")
    c.line(50, height - 110, width - 50, height - 110)

    # Table header
    y = height - 140
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "File")
    c.drawString(200, y, "Line")
    c.drawString(250, y, "Issue Type")
    c.drawString(400, y, "Severity")
    y -= 20
    c.setFont("Helvetica", 10)
    for v in vulnerabilities:
        if y < 60:
            c.showPage()
            y = height - 50
        c.setFillColor(severity_color(v.get("severity", v.get("risk", "low"))))
        c.drawString(50, y, str(v.get("file", "-"))[:30])
        c.drawString(200, y, str(v.get("line", "-")))
        c.drawString(250, y, str(v.get("issue_type", v.get("type", "-")))[:25])
        c.drawString(400, y, str(v.get("severity", v.get("risk", "-"))))
        c.setFillColor(colors.black)
        y -= 18
    c.save() 