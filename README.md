# CryptoCore

Учебная утилита для шифрования и расшифровки файлов с использованием **AES-128**.  

---

## Содержание

- [Требования](#требования)  
- [Сборка](#сборка)  

---

## Требования

- Linux (тестировано на Ubuntu).  
- Компилятор `gcc`.  
- Библиотека OpenSSL (заголовки и dev-пакет): `libssl-dev` (Debian/Ubuntu).  
- Make (для сборки).  
- Скрипты в `tests/` используют `openssl`, `dd`, `xxd`.

---

## Сборка

1. Установи зависимости (Debian/Ubuntu):
```bash
sudo apt update
sudo apt install build-essential libssl-dev openssl
