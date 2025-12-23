echo "=== Testing HMAC Basic Functionality ==="

echo "Hello, HMAC!" > test_message.txt

echo "Generating HMAC-SHA256..."
./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input test_message.txt

if [ $? -eq 0 ]; then
    echo "✓ HMAC generation test passed"
else
    echo "✗ HMAC generation test failed"
    exit 1
fi

# 
rm -f test_message.txt
echo "HMAC basic test completed!"