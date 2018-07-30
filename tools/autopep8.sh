#!/usr/bin/env bash

# $1: file/dir

if [ -f $1 ]; then
    autopep8 --in-place $1
else
    count=0
    for i in $(find $1 -name '*.py' -type f); do
        count=$(( ${count} + 1 ))
        echo "[${count}] autopep8 --in-place $i"
        autopep8 --in-place $i
    done
fi
