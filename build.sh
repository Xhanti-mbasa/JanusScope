#!/bin/bash

set -e

echo "Building HTTP Security Scanner..."
echo ""

if ! command -v node &> /dev/null; then
    echo "Node.js not found. Please install Node.js 18+"
    exit 1
fi

echo "Installing dependencies..."
npm install

echo ""
echo "Compiling TypeScript..."
npm run build

echo ""
echo "Build complete!"
echo ""
echo "Run scanner with:"
echo "  ./run.sh https://example.com"
echo "  npm start https://example.com"
echo "  node dist/scanner.js https://example.com"
