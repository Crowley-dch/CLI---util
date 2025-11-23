#!/bin/bash

echo "=== Testing Hash with NIST Vectors ==="

# Test vectors from NIST
echo -n "abc" > vector1.bin
echo -n "" > vector2.bin

# Expected SHA-256 hashes
EXPECTED1="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
EXPECTED2="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

echo "Testing NIST vector 1 ('abc')..."
RESULT1=$(./cryptocore dgst --algorithm sha256 --input vector1.bin | awk '{print $1}')

if [ "$RESULT1" = "$EXPECTED1" ]; then
    echo "✓ NIST vector 1: PASS"
else
    echo "✗ NIST vector 1: FAIL"
    echo "Expected: $EXPECTED1"
    echo "Got: $RESULT1"
    exit 1
fi

echo "Testing NIST vector 2 (empty)..."
RESULT2=$(./cryptocore dgst --algorithm sha256 --input vector2.bin | awk '{print $1}')

if [ "$RESULT2" = "$EXPECTED2" ]; then
    echo "✓ NIST vector 2: PASS"
else
    echo "✗ NIST vector 2: FAIL"
    echo "Expected: $EXPECTED2"
    echo "Got: $RESULT2"
    exit 1
fi

# Cleanup
rm -f vector1.bin vector2.bin
echo "All NIST vector tests passed!"