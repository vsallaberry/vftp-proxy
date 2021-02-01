#!/bin/sh

pfctl -a ftp-proxy -sn
pfctl -a ftp-proxy -sr
pfctl -a ftp-proxy -s Anchors

for a in `pfctl -a ftp-proxy -s Anchors`; do
    echo "* $a"
    pfctl -a "$a" -sn
    pfctl -a "$a" -sr
done

