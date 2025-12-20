echo "=== Testing HMAC Verification ==="

echo "Test data for HMAC verification" > verify_test.txt

echo "Generating HMAC..."
./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input verify_test.txt --output test_hmac.txt

if [ $? -ne 0 ]; then
    echo "✗ Failed to generate HMAC"
    exit 1
fi

echo "Verifying HMAC (should pass)..."
./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input verify_test.txt --verify test_hmac.txt

if [ $? -eq 0 ]; then
    echo "✓ HMAC verification test passed"
else
    echo "✗ HMAC verification test failed"
    exit 1
fi

rm -f verify_test.txt test_hmac.txt
echo "HMAC verification test completed!"