#!/usr/bin/env bash
# $1: poc-dir
# $2: strategy-dir
# $3: true/false 是否包含测试 poc/策略
# $4: true/false 是否构建镜像

print_usage() {
    echo "build.sh <poc-dir> <strategy-dir> <include_test> <build_docker_image>"
    echo "  include_test:  true/false, 默认 false: 是否包含测试 POC/策略"
    echo "  build_docker_image: 是否编译 docker 镜像"
    exit 1
}

rm -rf .resources
mkdir -p .resources
mkdir .resources/pocs
mkdir .resources/strategies
if [ "$3" == 'true' ]; then
    mkdir .resources/pocs/test
    mkdir .resources/strategies/test
    echo "添加测试 POC"
    cp -r test/resources/pocs/* .resources/pocs/test
    echo "添加测试策略"
    cp -r test/resources/strategies/* .resources/strategies/test
fi

if [ -d "$1" ]; then
    echo "添加 POC： $1"
    cp -r $1 .resources/pocs
else
    print_usage "目录 $1 不存在"
fi
if [ -d ""]; then
    echo "添加策略：$2"
    cp -r $2 .resources/strategies
else
    print_usage "目录 $2 不存在"
fi

echo "pipenv install --dev ."
pipenv install --dev .
pipenv run python scripts/utils.py --skip-syncing -v \
       --poc-dir .resources/pocs \
       --strategy-dir .resources/strategies

if [ "$4" == 'true' ]; then
    docker build -t cscan:0.1 .
fi
