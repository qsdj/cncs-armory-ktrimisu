#!/usr/bin/env bash
# $1: poc-dir
# $2: strategy-dir
# $3: true/false 是否包含测试 poc/策略

print_usage() {
    echo "build.sh <poc-dir> <strategy-dir> [true/false, default to be false, include test poc/strategy]"
    exit 1
}

rm -rf .resources
mkdir -p .resources
mkdir .resources/pocs
mkdir .resources/strategies
if [ "$3" == 'true' ]; then
    mkdir .resources/pocs/test
    mkdir .resources/strategies/test
    cp -r test/resources/pocs/* .resources/pocs/test
    cp -r test/resources/strategies/* .resources/strategies/test
fi

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
