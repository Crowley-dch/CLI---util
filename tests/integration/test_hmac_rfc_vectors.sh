echo "=== Testing HMAC with RFC 4231 Vectors ==="

echo -n "Hi There" > rfc_test1.txt
EXPECTED1="b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

echo "Testing RFC 4231 Test Case 1..."
RESULT1=$(./cryptocore dgst --algorithm sha256 --hmac --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b --input rfc_test1.txt | awk '{print $1}')

if [ "$RESULT1" = "$EXPECTED1" ]; then
    echo "✓ RFC 4231 Test Case 1 passed"
else
    echo "✗ RFC 4231 Test Case 1 failed"
    echo "Expected: $EXPECTED1"
    echo "Got: $RESULT1"
    exit 1
fi

rm -f rfc_test1.txt
echo "RFC 4231 vector tests completed!"