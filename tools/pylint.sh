#!/usr/bin/env bash

# $1: file/dir

if [ -f $1 ]; then
    pylint -E $1
else
    count=0
    for i in $(find $1 -name '*.py' -type f); do
        count=$(( ${count} + 1 ))
        echo "[${count}] pylint -E $i"
        pylint -E $i
    done
fi
