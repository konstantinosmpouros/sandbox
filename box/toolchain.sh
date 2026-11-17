#!/bin/sh
# The box's document toolchain, shared by box/Dockerfile and the runner's `box`
# stage (runner/Dockerfile) so the two can never drift. Run once, as root, at
# build time; the box itself has no network and no package manager use.
#
# What it adds to the Python library set (requirements.txt), and why: the
# document skills (docx, xlsx, pptx, pdf) do more than write a file.
#   * LibreOffice (writer, calc, impress; no GUI): renders a document to PDF so
#     the agent can look at what it made, and recalculates a workbook's
#     formulas (a cell written by openpyxl has no cached value until then).
#   * poppler-utils: pdftoppm (a page as an image, for that visual check) and
#     pdftotext.
#   * pandoc: reads a .docx as text and converts markdown to .docx.
#   * qpdf: merges, splits and repairs PDFs.
#   * zip: repacks an unpacked .docx / .pptx after an XML edit.
#   * Node with docx (docx-js) and pptxgenjs: how the skills build .docx and
#     .pptx (richer layouts than python-docx / python-pptx); pdf-lib fills PDF
#     forms; react, react-dom, react-icons and sharp render icons into slides.
#     npm is used here only, then removed: the box runs `node`, never `npm`.
#   * Fonts with Greek and the metric-compatible Office faces (Liberation for
#     Arial / Times / Courier, Carlito for Calibri, Caladea for Cambria), so a
#     PDF never shows boxes for Greek and a document keeps its layout.
set -eu

export DEBIAN_FRONTEND=noninteractive
# LibreOffice from bookworm-backports (25.2), everything else from stable.
# Bookworm's own 7.4 aborts (SIGABRT in vcl) when headless LibreOffice runs a
# Basic macro, which is how the xlsx skill recalculates formulas and the docx
# skill accepts tracked changes. Backports is Debian's own, signed archive.
echo "deb http://deb.debian.org/debian bookworm-backports main" > /etc/apt/sources.list.d/backports.list
apt-get update
apt-get install -y --no-install-recommends -t bookworm-backports \
    libreoffice-writer-nogui \
    libreoffice-calc-nogui \
    libreoffice-impress-nogui
apt-get install -y --no-install-recommends \
    poppler-utils \
    pandoc \
    qpdf \
    zip \
    nodejs \
    npm \
    fonts-dejavu-core \
    fonts-liberation2 \
    fonts-crosextra-carlito \
    fonts-crosextra-caladea \
    fontconfig

# Global packages land in /usr/local/lib/node_modules. Node looks for a package
# in node_modules/ of the script's folder and every parent up to /, so a
# /node_modules link makes them found from anywhere (no NODE_PATH: the box's
# environment stays the runner's allowlist). Exact versions: the box is a release.
npm install --global --omit=dev --no-audit --no-fund --no-update-notifier \
    docx@9.5.1 \
    pptxgenjs@3.12.0 \
    pdf-lib@1.17.1 \
    react@18.3.1 \
    react-dom@18.3.1 \
    react-icons@5.5.0 \
    sharp@0.34.3
npm cache clean --force
ln -s /usr/local/lib/node_modules /node_modules

apt-get purge -y --auto-remove npm
# nodejs itself must stay (purging npm can mark it auto-installed).
apt-mark manual nodejs >/dev/null
apt-get install -y --no-install-recommends nodejs

# LibreOffice finds its profile through the passwd entry, which the box's uid
# does not have, so a bare `soffice` dies with "User installation could not be
# completed". This wrapper (first on the box's PATH) puts the profile under the
# writable HOME (/tmp), unless the caller chose one.
cat > /usr/local/bin/soffice <<'SH'
#!/bin/sh
case " $* " in
  *UserInstallation=*) exec /usr/bin/soffice "$@" ;;
  *) exec /usr/bin/soffice "-env:UserInstallation=file://${HOME:-/tmp}/.libreoffice" "$@" ;;
esac
SH
chmod 0755 /usr/local/bin/soffice
ln -sf /usr/local/bin/soffice /usr/local/bin/libreoffice

fc-cache -f
rm -rf /var/lib/apt/lists/* /root/.npm /root/.cache /tmp/*

# Fail the build, not a user's call, when a piece is missing.
soffice --version
pdftoppm -v
pandoc --version | head -n 1
qpdf --version | head -n 1
zip -v | sed -n 2p
cd /tmp && node -e "require('docx'); require('pptxgenjs'); require('pdf-lib'); require('sharp'); console.log('node packages ok')"
cd / && fc-list | grep -qi liberation
