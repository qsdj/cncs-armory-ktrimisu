#!/usr/bin/env bash
# $1: true/false skip-indexing

echo_title() {
    echo "=================================================="
    echo "| $1"
}

build_cscan() {
    cd CScanPoc
    if [ "$1" == "true" ]; then
        docker build -t cscan:0.1 .
    else
        ./build.sh ../pocs ../strategies true
    fi
    cd ..
}

build_asset_finder() {
    cd utility/AssetFinder/
    docker build -t asset-finder:0.1 .
    cd ../..
}

build_asset_identification() {
    cd utility/AssetIdentification/
    docker build -t asset-identifier:0.1 .
    cd ../..
}

echo_title "build cscan"
build_cscan

echo_title "build asset finder"
build_asset_finder

echo_title "build asset identifier"
build_asset_identification
