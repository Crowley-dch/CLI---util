echo "=== Testing HMAC Tamper Detection ==="

echo "Original content" > original.txt

./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input original.txt --output original_hmac.txt

echo "Tampered content" > original.txt

echo "Verifying HMAC after tampering (should fail)..."
./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input original.txt --verify original_hmac.txt

if [ $? -ne 0 ]; then
    echo "✓ Tamper detection test passed"
else
    echo "✗ Tamper detection test failed"
    exit 1
fi

rm -f original.txt original_hmac.txt
echo "HMAC tamper detection test completed!"