#!/bin/sh
# The document toolchain, exercised the way the document skills use it, inside a
# box (read-only root, noexec /tmp as HOME, no network, non-root). Run from the
# output dir; prints one line per check and exits non-zero on the first failure.
# Used by the spike (gate item "toolchain") and by hand after a box change.
set -eu
cd "${1:-.}"

# 1. A .docx from python-docx, rendered to PDF by LibreOffice, then to an image.
python3 - <<'PY'
from docx import Document
d = Document()
d.add_heading("Έκθεση δοκιμής", 0)
d.add_paragraph("Καλημέρα κόσμε. Hello world.")
d.save("check.docx")
PY
soffice --headless --norestore --convert-to pdf --outdir . check.docx >/dev/null 2>&1
test -s check.pdf
pdftoppm -png -r 50 -f 1 -l 1 check.pdf page >/dev/null
ls page*.png >/dev/null
pdftotext check.pdf - | grep -q "Καλημέρα"
echo "ok docx -> pdf -> png (greek text kept)"

# 2. A formula written by openpyxl has no value until LibreOffice recalculates it.
python3 - <<'PY'
from openpyxl import Workbook
wb = Workbook(); ws = wb.active
ws["A1"], ws["A2"], ws["A3"] = 2, 3, "=SUM(A1:A2)"
wb.save("check.xlsx")
PY
mkdir -p recalc
soffice --headless --norestore --convert-to xlsx --outdir recalc check.xlsx >/dev/null 2>&1
python3 - <<'PY'
from openpyxl import load_workbook
value = load_workbook("recalc/check.xlsx", data_only=True).active["A3"].value
assert value == 5, value
PY
echo "ok xlsx formulas recalculated"

# 3. docx-js and pptxgenjs from the global Node packages (found through /node_modules).
cat > check.js <<'JS'
const fs = require("fs");
const { Document, Packer, Paragraph } = require("docx");
const pptxgen = require("pptxgenjs");
(async () => {
  const doc = new Document({ sections: [{ children: [new Paragraph("Γεια από docx-js")] }] });
  fs.writeFileSync("node.docx", await Packer.toBuffer(doc));
  const pres = new pptxgen();
  pres.addSlide().addText("Γεια από pptxgenjs", { x: 1, y: 1, fontSize: 24 });
  await pres.writeFile({ fileName: "node.pptx" });
})().catch((e) => { console.error(e); process.exit(1); });
JS
node check.js
test -s node.docx && test -s node.pptx
soffice --headless --norestore --convert-to pdf --outdir . node.pptx >/dev/null 2>&1
test -s node.pdf
echo "ok docx-js + pptxgenjs (pptx renders)"

# 4. A PDF with Greek from reportlab with a system TTF, read back by pypdf; qpdf merges.
python3 - <<'PY'
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
pdfmetrics.registerFont(TTFont("Liberation", "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf"))
c = canvas.Canvas("greek.pdf"); c.setFont("Liberation", 14); c.drawString(72, 720, "Αγία Σοφία"); c.save()
from pypdf import PdfReader
assert "Σοφία" in PdfReader("greek.pdf").pages[0].extract_text()
PY
qpdf --empty --pages greek.pdf check.pdf -- merged.pdf
python3 -c "from pypdf import PdfReader; assert len(PdfReader('merged.pdf').pages) >= 2"
echo "ok reportlab greek + pypdf + qpdf"

# 5. The platform skills' own scripts (magenticx plan 44), run as their SKILL.md says.
S=/platform_skills
python3 $S/xlsx/scripts/recalc.py check.xlsx 120 | grep -q '"status": "success"'
python3 $S/docx/scripts/office/soffice.py --headless --convert-to pdf --outdir skill check.docx >/dev/null 2>&1
test -s skill/check.pdf
python3 $S/docx/scripts/office/validate.py node.docx >/dev/null   # docx-js, as the skill builds it
python3 $S/pptx/scripts/thumbnail.py node.pptx thumbs >/dev/null
ls thumbs*.jpg >/dev/null
python3 $S/pptx/scripts/slide_text.py node.pptx | grep -q "pptxgenjs"
mkdir -p pages && python3 $S/pdf/scripts/convert_pdf_to_images.py check.pdf pages >/dev/null
test -s pages/page_1.png
(mkdir -p unpacked && cd unpacked && python3 -c "import zipfile; zipfile.ZipFile('../node.docx').extractall('.')" \
  && rm -f ../repacked.docx && zip -XrDyq ../repacked.docx .)
python3 $S/docx/scripts/office/validate.py repacked.docx --original node.docx >/dev/null
echo "ok platform skills (recalc, soffice, validate, thumbnail, slide_text, pdf pages, unpack/zip)"

echo "toolchain ok"
