#!/bin/bash
for r in "$@"; do echo "== $r"; bash /mnt/f/rsa-rs/scripts/baseline.sh $r; done
echo BASEDONE
