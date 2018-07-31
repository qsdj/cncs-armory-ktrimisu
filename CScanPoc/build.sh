#!/usr/bin/env bash
# $1: poc-dir
# $2: strategy-dir

print_usage() {
    echo "build.sh <poc-dir> <strategy-dir>: $1"
    exit 1
}

rm -rf .resources
mkdir -p .resources
if [ -d "$1" ]; then
    cp -r $1 .resources/pocs
else
    print_usage "目录 $1 不存在"
fi
if [ -d ""]; then
    cp -r $2 .resources/strategies
else
    print_usage "目录 $2 不存在"
fi
pipenv run python scripts/utils.py --skip-syncing -v \
       --poc-dir .resources/pocs \
       --strategy-dir .resources/strategies
docker build -t cscan:0.1 .
