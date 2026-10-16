#!/usr/bin/env python3
"""Create local scientific figures and a PDF from the measured study draft."""
import argparse
from collections import Counter
import hashlib
from html import escape
import importlib.metadata
import json
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("MPLCONFIGDIR", str(ROOT / "experiments/.cache/matplotlib"))
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import markdown
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def figures(summaries, output):
    totals = {}
    for path in summaries:
        data = json.loads(path.read_text())
        if data["run_status"] != "ok":
            raise RuntimeError("Invalid summary")
        for suite in data["live_observer_suites"]:
            protocol = suite["suite"].split("-")[1]
            key = (data["client_runtime"], protocol)
            item = totals.setdefault(key, {"counts": Counter(), "stage": data["study_stage"],
                                            "support": suite["support"]})
            if item["stage"] != data["study_stage"]:
                raise RuntimeError("Do not pool screening and main results")
            item["counts"].update({k: v for k, v in suite["summary"].items() if isinstance(v, int)})
    labels, coverage, recall, annotations, bars = [], [], [], [], []
    for (runtime, protocol), item in sorted(totals.items()):
        counts = item["counts"]
        labels.append(runtime.capitalize() + " " + ("HTTP/1.1" if protocol == "http1" else "HTTP/2"))
        coverage.append(100 * counts["exact_attempts"] / counts["emitted_usage_attempts"])
        recall.append(100 * counts["matched_attempts"] / counts["server_attempts"])
        annotations.append(f"{counts['exact_attempts']:,}/{counts['emitted_usage_attempts']:,}")
        bars.append(item["support"] == "qualified_supported_candidate")
    fig, ax = plt.subplots(figsize=(8.2, 4.7))
    fig.subplots_adjust(left=.19, right=.98, top=.87, bottom=.29)
    y = list(range(len(labels)))
    a = ax.barh([v - .18 for v in y], coverage, height=.32, label="Exact reported usage / emitted usage", color="#326f9d")
    b = ax.barh([v + .18 for v in y], recall, height=.32, label="Identity-matched attempts / received attempts", color="#9fb9c6")
    for i, patch in enumerate(a):
        if not bars[i]:
            patch.set_hatch("///")
            patch.set_facecolor("#ccd1d6")
            b[i].set_hatch("///")
            b[i].set_facecolor("#e1e4e7")
        ax.text(min(coverage[i] + 1, 97), i - .18, annotations[i], va="center", fontsize=8,
                ha="right" if coverage[i] > 90 else "left")
    ax.set_yticks(y, labels)
    ax.invert_yaxis()
    ax.set_xlim(0, 115)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_xlabel("Observed fraction (%)")
    ax.spines[["top", "right"]].set_visible(False)
    handles, legend_labels = ax.get_legend_handles_labels()
    fig.legend(handles, legend_labels, loc="center left", bbox_to_anchor=(.19, .13), fontsize=8, frameon=False)
    ax.set_title("Accounting coverage in the local workload", loc="left", fontsize=12)
    fig.text(.02, .02, "Hatching: clean usage was not reproduced in that session.\nFractions describe this workload; no ordinary-case confidence interval.", fontsize=7)
    files = []
    for suffix in ("png", "pdf", "svg"):
        path = output / ("accounting-coverage." + suffix)
        fig.savefig(path, dpi=220, bbox_inches="tight", metadata={"Creator": "Local accounting-study renderer"})
        files.append(path)
    plt.close(fig)
    data_file = output / "accounting-coverage-data.json"
    data_file.write_text(json.dumps([
        {"runtime": key[0], "protocol": key[1], "stage": item["stage"],
         "support": item["support"], "counts": dict(item["counts"])} for key, item in sorted(totals.items())], indent=2) + "\n")
    return [*files, data_file]


def inline(element):
    text = escape(element.text or "")
    for child in element:
        content = inline(child)
        if child.tag in ("strong", "b"):
            text += "<b>" + content + "</b>"
        elif child.tag in ("em", "i"):
            text += "<i>" + content + "</i>"
        elif child.tag == "code":
            text += '<font name="Courier">' + content + "</font>"
        elif child.tag == "a":
            href = child.attrib.get("href", "")
            text += ('<link href="' + escape(href, quote=True) + '" color="#235a85">' + content + "</link>") if href.startswith("https://") else content
        elif child.tag != "img":
            text += content
        text += escape(child.tail or "")
    return text


def manuscript_pdf(source, target):
    font = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
    if font.is_file():
        pdfmetrics.registerFont(TTFont("StudySans", str(font)))
        pdfmetrics.registerFont(TTFont("StudySans-Bold", str(font.with_name("DejaVuSans-Bold.ttf"))))
        pdfmetrics.registerFont(TTFont("StudySans-Oblique", str(font.with_name("DejaVuSans-Oblique.ttf"))))
        pdfmetrics.registerFont(TTFont("StudySans-BoldOblique", str(font.with_name("DejaVuSans-BoldOblique.ttf"))))
        pdfmetrics.registerFontFamily("StudySans", normal="StudySans", bold="StudySans-Bold", italic="StudySans-Oblique", boldItalic="StudySans-BoldOblique")
    face = "StudySans" if font.is_file() else "Helvetica"
    styles = getSampleStyleSheet()
    for name in ("Normal", "Title", "Heading1", "Heading2", "Heading3"):
        styles[name].fontName = face
    styles["Normal"].fontSize, styles["Normal"].leading = 9, 13
    styles["Normal"].spaceAfter = 7
    styles["Title"].fontSize, styles["Title"].leading = 19, 23
    styles.add(ParagraphStyle("Cell", parent=styles["Normal"], fontSize=7, leading=9, spaceAfter=0))
    styles.add(ParagraphStyle("Caption", parent=styles["Normal"], fontSize=8, leading=10, alignment=TA_CENTER))
    text = source.read_text()
    # Mermaid remains available in Markdown; the PDF uses the prose methods.
    text = re.sub(r"```mermaid\n.*?```", "The client, fixture server and observer write separate ledgers; the scorer compares their identity and usage evidence.", text, flags=re.S)
    root = ET.fromstring("<document>" + markdown.markdown(text, extensions=["tables", "fenced_code"]) + "</document>")
    story = []
    width = A4[0] - 96
    for node in root:
        if node.tag in ("h1", "h2", "h3"):
            style = "Title" if node.tag == "h1" else "Heading2" if node.tag == "h2" else "Heading3"
            story.append(Paragraph(inline(node), styles[style]))
        elif node.tag == "p":
            images = list(node.iter("img"))
            if images:
                for img in images:
                    path = (source.parent / img.attrib["src"]).resolve()
                    if not path.is_relative_to(ROOT):
                        raise RuntimeError("Image must be project-local")
                    from PIL import Image as PILImage
                    with PILImage.open(path) as raster:
                        w, h = raster.size
                    story.append(Image(str(path), width=width, height=width * h / w))
            else:
                story.append(Paragraph(inline(node), styles["Normal"]))
        elif node.tag in ("ul", "ol"):
            for i, item in enumerate(node):
                prefix = str(i + 1) + ". " if node.tag == "ol" else "• "
                story.append(Paragraph(prefix + inline(item), styles["Normal"]))
        elif node.tag == "table":
            rows = [[Paragraph(inline(cell), styles["Cell"]) for cell in row] for row in node.iter("tr")]
            if rows:
                table = Table(rows, colWidths=[width / len(rows[0])] * len(rows[0]), repeatRows=1, hAlign="LEFT")
                table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8edf1")),
                                           ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                           ("LINEBELOW", (0, 0), (-1, 0), .5, colors.grey),
                                           ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
                story.extend([table, Spacer(1, 9)])
    def footer(canvas, doc):
        canvas.setFont(face, 7)
        canvas.drawString(48, 28, "Working manuscript — human review and publication destination pending")
        canvas.drawRightString(A4[0] - 48, 28, str(doc.page))
    doc = SimpleDocTemplate(str(target), pagesize=A4, rightMargin=48, leftMargin=48,
                            topMargin=42, bottomMargin=45, title="When Passive LLM Usage Accounting Has Enough Evidence",
                            author="Hoang Le", creator="Local accounting-study renderer")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, nargs="+")
    parser.add_argument("--manuscript", type=Path, default=Path("docs/research/accounting-manuscript.md"))
    parser.add_argument("--output", type=Path, default=Path("experiments/results/accounting-manuscript.pdf"))
    args = parser.parse_args()
    output = args.output.resolve()
    if output.parent != ROOT / "experiments/results":
        parser.error("Output must be directly inside experiments/results")
    output.parent.mkdir(parents=True, exist_ok=True)
    source = args.manuscript.resolve()
    if not source.is_relative_to(ROOT / "docs/research"):
        parser.error("Use the project-local research manuscript")
    generated = figures(args.summary, output.parent) if args.summary else []
    manuscript_pdf(source, output)
    provenance = {"manuscript_sha256": sha(source), "pdf_sha256": sha(output),
                  "renderer_sha256": sha(Path(__file__)),
                  "report_requirements_sha256": sha(ROOT / "experiments/requirements-report.txt"),
                  "summaries": {p.name: sha(p) for p in args.summary or []},
                  "figure_sha256": {p.name: sha(p) for p in generated},
                  "packages": {n: importlib.metadata.version(n) for n in ("matplotlib", "reportlab", "Markdown")}}
    output.with_suffix(".provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print("Rendered " + output.relative_to(ROOT).as_posix() + "; no upload")


if __name__ == "__main__":
    main()
