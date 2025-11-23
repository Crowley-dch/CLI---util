
echo "=== Testing SHA-256 Hash ==="

echo "Hello, CryptoCore!" > test_input.bin

echo "Testing SHA-256 hash..."
./cryptocore dgst --algorithm sha256 --input test_input.bin

if [ $? -eq 0 ]; then
    echo "✓ SHA-256 test passed"
else
    echo "✗ SHA-256 test failed"
    exit 1
fi

rm -f test_input.bin
echo "All SHA-256 tests completed!"