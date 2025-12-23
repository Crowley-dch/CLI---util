
## 1. шифрование с  gcm: 
```bash
./cryptocore --algorithm aes --mode gcm --encrypt \
           --key a1b2c3d4e5f67890abcdef1234567890 \
           --input test.txt
```
 **созданные файлы:**
```bash
 ls -la test.txt*
```
 **дешифрование:**
 ```bash
 ./cryptocore --algorithm aes --mode gcm --decrypt \
           --key a1b2c3d4e5f67890abcdef1234567890 \
           --input test.txt.enc \
           --output test2.txt
```
**проверка целостности:** 
```bash
diff test.txt test2.txt && echo "Файлы идентичны"

```
##2. Генерация ключа из пароля
```bash
./cryptocore derive --password "Kafedra_izi" \
                  --generate-salt \
                  --iterations 100000
```
## 3.  создание и проверка подписи: 
```bash
./cryptocore dgst --algorithm sha256 --hmac \
                --key 00112233445566778899aabbccddeeff \
                --input doc.pdf \
                --verify signature.txt
```
## 4. GCM
```bash
cryptocore --algorithm aes --mode gcm --encrypt \
           --key a1b2c3d4e5f67890abcdef1234567890 \
           --input document.pdf \
           --output document.pdf.enc
```
## 5. Шифрование со случайным ключом 
```bash
./cryptocore --algorithm aes --mode gcm --encrypt \
           --input test.txt
```
## 6. генерация ключа с дополнительными параметрами
```bash
./cryptocore derive --password "hello_izi" \
                  --iterations 500000 \
                  --length 64 \
                  --output key.bin
```
