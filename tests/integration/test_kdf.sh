echo "=== Testing KDF functionality ==="

echo "Test 1: RFC 6070 vector 1"
./cryptocore derive --password "password" --salt "73616c74" --iterations 1 --length 20
echo "Expected: 0c60c80f961f0e71f3a9b524af6012062fe037a6 73616c74"
echo ""
echo "Test 2: Auto-generated salt"
./cryptocore derive --password "test123" --iterations 1000 --length 32
echo ""

echo "Test 3: Different key lengths"
./cryptocore derive --password "test" --salt "112233" --iterations 100 --length 16 --quiet
./cryptocore derive --password "test" --salt "112233" --iterations 100 --length 64 --quiet
echo ""

echo -n "filepassword123" > testpass.txt
echo "Test 4: Read password from file"
./cryptocore derive --password-file testpass.txt --salt "aabbcc" --iterations 100 --length 16
rm -f testpass.txt
echo ""

echo "=== KDF tests completed ==="