#!/usr/bin/env bash
# $1: poc-dir

if [ ! "$1" ]; then
   echo 'build.sh <poc-dir>'
   exit 1
fi

rm -rf .pocs
cp -r $1 .pocs
pipenv run python scripts/utils.py --poc-dir .pocs --skip-syncing -v
docker build -t cscan:0.1 .
