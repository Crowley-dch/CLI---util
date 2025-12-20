echo "=== Testing BLAKE2b Hash ==="

echo "Testing BLAKE2b hashing" > test_input.bin

echo "Testing BLAKE2b hash..."
./cryptocore dgst --algorithm blake2b --input test_input.bin

if [ $? -eq 0 ]; then
    echo "✓ BLAKE2b test passed"
else
    echo "✗ BLAKE2b test failed"
    exit 1
fi

rm -f test_input.bin
echo "All BLAKE2b tests completed!"