#!/bin/bash

if [ ! -d "dist" ]; then
    echo "Not built yet. Run ./build.sh first"
    exit 1
fi

node dist/scanner.js "$@"
