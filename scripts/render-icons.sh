#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Renders the launcher and store icons from assets/images/ipdoit-icon.svg.
# Needs rsvg-convert (librsvg2-bin). The PNGs are committed, so a normal build does
# not need this script.

set -eu
cd "$(dirname "$0")/.."
src=assets/images/ipdoit-icon.svg
out=assets/images
rsvg-convert -w 100 -h 100 "$src" -o "$out/ipdoit-for-cardputer-zero_100.png"
rsvg-convert -w 80 -h 80 "$src" -o "$out/ipdoit-for-cardputer-zero_80.png"
cp "$out/ipdoit-for-cardputer-zero_100.png" "$out/ipdoit-for-cardputer-zero.png"
rsvg-convert -w 256 -h 256 "$src" -o "$out/ipdoit-store-icon.png"
echo "rendered icons into $out"
