set -euo pipefail

echo "Запуск тестов..."

# Даем права на выполнение всем скриптам
chmod +x ./tests/integration/*.sh
chmod +x ./tests/scripts/*.sh

# Определяем пути к файлам
HMAC_FILE="./src/mac/hmac.c"
SHA256_FILE="./src/hash/sha256.c"
HKDF_FILE="./src/kdf/hkdf.c"
PBKDF2_FILE="./src/kdf/pbkdf2.c"

echo "Используемые файлы:"
echo "- HMAC: $HMAC_FILE"
echo "- SHA256: $SHA256_FILE"
echo "- HKDF: $HKDF_FILE"
echo "- PBKDF2: $PBKDF2_FILE"

# Проверяем наличие всех файлов
for file in "$HMAC_FILE" "$SHA256_FILE" "$HKDF_FILE" "$PBKDF2_FILE"; do
    if [ ! -f "$file" ]; then
        echo "Ошибка: файл не найден: $file"
        exit 1
    fi
done

# Создаем временные копии unit-тестов с исправленными путями
echo "Подготовка unit-тестов..."
mkdir -p /tmp/test_build

# Исправляем пути в test_hkdf.c (добавляем stdlib.h)
sed 's|#include "../src/kdf/hkdf.h"|#include "src/kdf/hkdf.h"|;
     s|#include <assert.h>|#include <assert.h>\n#include <stdlib.h>|' \
    ./tests/unit/test_hkdf.c > /tmp/test_build/test_hkdf_fixed.c

# Исправляем пути в test_kdf_comprehensive.c (добавляем stdlib.h)
sed 's|#include "../src/kdf/hkdf.h"|#include "src/kdf/hkdf.h"|;
     s|#include "../src/kdf/pbkdf2.h"|#include "src/kdf/pbkdf2.h"|;
     s|#include <stdio.h>|#include <stdio.h>\n#include <stdlib.h>|' \
    ./tests/unit/test_kdf_comprehensive.c > /tmp/test_build/test_kdf_comprehensive_fixed.c

# Исправляем пути в test_kdf_rfc.c (добавляем stdlib.h)
sed 's|#include "../src/kdf/hkdf.h"|#include "src/kdf/hkdf.h"|;
     s|#include "../src/kdf/pbkdf2.h"|#include "src/kdf/pbkdf2.h"|;
     s|#include <stdio.h>|#include <stdio.h>\n#include <stdlib.h>|' \
    ./tests/unit/test_kdf_rfc.c > /tmp/test_build/test_kdf_rfc_fixed.c

# Собираем unit-тесты
echo "Компиляция unit-тестов..."

# Общие флаги компиляции
CFLAGS="-I. -Wall"

# Для test_hkdf
echo "Компиляция test_hkdf..."
gcc $CFLAGS -o ./tests/unit/test_hkdf \
    /tmp/test_build/test_hkdf_fixed.c \
    "$HKDF_FILE" \
    "$HMAC_FILE" \
    "$SHA256_FILE"

# Для test_kdf_comprehensive
echo "Компиляция test_kdf_comprehensive..."
gcc $CFLAGS -o ./tests/unit/test_kdf_comprehensive \
    /tmp/test_build/test_kdf_comprehensive_fixed.c \
    "$HKDF_FILE" \
    "$PBKDF2_FILE" \
    "$HMAC_FILE" \
    "$SHA256_FILE"

# Для test_kdf_rfc
echo "Компиляция test_kdf_rfc..."
gcc $CFLAGS -o ./tests/unit/test_kdf_rfc \
    /tmp/test_build/test_kdf_rfc_fixed.c \
    "$HKDF_FILE" \
    "$PBKDF2_FILE" \
    "$HMAC_FILE" \
    "$SHA256_FILE"

# Тесты из integration/
echo "Запуск integration тестов..."
for test in ./tests/integration/*.sh; do
    if [ -x "$test" ]; then
        echo "=== Запуск: $(basename "$test") ==="
        if ! "$test"; then
            echo "Тест завершился с ошибкой: $(basename "$test")"
            # Продолжаем выполнение других тестов
        fi
    fi
done

# Тесты из scripts/
echo "Запуск scripts тестов..."
for test in ./tests/scripts/*.sh; do
    if [ -x "$test" ]; then
        echo "=== Запуск: $(basename "$test") ==="
        if ! "$test"; then
            echo "Тест завершился с ошибкой: $(basename "$test")"
            # Продолжаем выполнение других тестов
        fi
    fi
done

# Запуск unit-тестов
echo "Запуск unit тестов..."
if [ -x "./tests/unit/test_hkdf" ]; then
    echo "=== Запуск test_hkdf ==="
    if ! ./tests/unit/test_hkdf; then
        echo "Тест завершился с ошибкой: test_hkdf"
    fi
fi

if [ -x "./tests/unit/test_kdf_comprehensive" ]; then
    echo "=== Запуск test_kdf_comprehensive ==="
    if ! ./tests/unit/test_kdf_comprehensive; then
        echo "Тест завершился с ошибкой: test_kdf_comprehensive"
    fi
fi


echo "[SUMMARY] Тестирование завершено"

# Очистка временных файлов
rm -rf /tmp/test_build