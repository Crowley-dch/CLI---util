echo "=== Testing HMAC Wrong Key Detection ==="

echo "Test data" > key_test.txt

./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input key_test.txt --output key_hmac.txt

echo "Verifying HMAC with wrong key (should fail)..."
./cryptocore dgst --algorithm sha256 --hmac --key ffeeddccbbaa99887766554433221100 --input key_test.txt --verify key_hmac.txt

if [ $? -ne 0 ]; then
    echo "✓ Wrong key detection test passed"
else
    echo "✗ Wrong key detection test failed"
    exit 1
fi

rm -f key_test.txt key_hmac.txt
echo "HMAC wrong key detection test completed!"