#!/bin/bash

try() {
    expected="$1"
    input="$2"

    ./scc "$input" > tmp || exit 1
    chmod +x tmp
    ./tmp
    actual="$?"


    if [ "$actual" = "$expected" ]; then
        echo "$input => $actual"
    else
        echo "test.sh: error: $input => $expected expected, but got $input => $actual"
        exit 1
    fi
}

try 0 0
try 42 42
try 20 20
try 21 "5+20-4"
try 20 "4-4+20"
try 20 " 4 - 4 +   20 "
try 48 "20  + 20  -  4 +  4      + 8 "

echo test.sh: success: all tests passed