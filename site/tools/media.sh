#!/usr/bin/env bash
# Regenerate the site's media from the repo's own assets (needs ffmpeg).
# Outputs are committed; the build only copies them.
#
#   field.png  the hero's 1-bit cloud: a walkthrough frame blurred, faded to
#              nothing at the bottom, error-diffused to one bit, stored as an
#              alpha mask so CSS can paint it in the theme's ink
set -euo pipefail
cd "$(dirname "$0")/../.."
out=site/media
mkdir -p "$out"

ffmpeg -loglevel error -y -ss 40 -i assets/walkthrough.mp4 -frames:v 1 -filter_complex "
  [0:v]format=gray,gblur=sigma=40,scale=360:-1:flags=area,normalize=smoothing=0,eq=gamma=1.6,
       geq=lum='lum(X,Y)*pow(max(0,1-Y/H),1.2)',format=monob,format=gray,split[a][b];
  [a]lutyuv=y=255[white];[white][b]alphamerge,format=ya8" "$out/field.png"
ls -la "$out"
