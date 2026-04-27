#!/bin/bash

if [ $# -lt 1 ]; then
    echo "Использование: $0 <номер_краша>"
    echo "Пример: $0 1      # анализирует первый краш"
    echo "Пример: $0 all    # анализирует все краши"
    exit 1
fi

CRASH_NUM="$1"
CRASH_DIR="results/default/crashes"

if [ "$CRASH_NUM" = "all" ]; then
    echo "Анализ всех крашей..."
    for i in $(seq 1 $(ls "$CRASH_DIR" | wc -l)); do
        echo ""
        echo "========================================"
        ./analyze_one_crash.sh $i
    done
    exit 0
fi

# Получаем конкретный краш
CRASHES=($(ls "$CRASH_DIR"/id* | sort))
if [ ${#CRASHES[@]} -eq 0 ]; then
    echo "Краши не найдены!"
    exit 1
fi

if [ "$CRASH_NUM" -gt "${#CRASHES[@]}" ] || [ "$CRASH_NUM" -lt 1 ]; then
    echo "Номер краша должен быть от 1 до ${#CRASHES[@]}"
    exit 1
fi

CRASH="${CRASHES[$((CRASH_NUM-1))]}"
CRASH_NAME=$(basename "$CRASH")

echo "=== ДЕТАЛЬНЫЙ АНАЛИЗ КРАША #$CRASH_NUM ==="
echo "Файл: $CRASH_NAME"
echo ""

# 1. Информация о файле
echo "1. ИНФОРМАЦИЯ О ФАЙЛЕ:"
echo "-------------------"
echo "Размер: $(stat -c%s "$CRASH") байт"
echo "Права: $(stat -c%A "$CRASH")"
echo "Тип: $(file "$CRASH")"
echo ""

# 2. HEX дамп (первые 64 байта)
echo "2. HEX ДАМП (первые 64 байта):"
echo "---------------------------"
hexdump -C -n 64 "$CRASH"
echo ""

# 3. Запуск с ASAN
echo "3. ЗАПУСК С ADDRESSSANITIZER:"
echo "---------------------------"
ASAN_OPTIONS=abort_on_error=1:symbolize=1 ./jhead "$CRASH" 2>&1 | head -30
echo ""

# 4. Анализ с GDB
echo "4. GDB BACKTRACE:"
echo "---------------"
gdb -q --batch \
    -ex "run $CRASH" \
    -ex "backtrace" \
    -ex "info registers" \
    -ex "quit" ./jhead 2>&1 | grep -A 20 "Program received signal\|#0"
echo ""

# 5. Классификация
echo "5. КЛАССИФИКАЦИЯ УЯЗВИМОСТИ:"
echo "--------------------------"
SIG=$(echo "$CRASH_NAME" | grep -o 'sig:[0-9]*' | cut -d: -f2)

if [ "$SIG" = "11" ]; then
    # Для SIGSEGV определяем точнее
    GDB_OUT=$(gdb -q --batch -ex "run $CRASH" -ex "backtrace" ./jhead 2>&1)
    
    if echo "$GDB_OUT" | grep -i "strcpy\|strcat\|sprintf"; then
        echo "Тип: BUFFER OVERFLOW (переполнение буфера)"
        echo "Причина: Использование небезопасных функций (strcpy и др.)"
    elif echo "$GDB_OUT" | grep -i "malloc\|free"; then
        echo "Тип: HEAP CORRUPTION (повреждение кучи)"
        echo "Причина: Неправильная работа с динамической памятью"
    elif echo "$GDB_OUT" | grep -i "null\|0x0"; then
        echo "Тип: NULL POINTER DEREFERENCE"
        echo "Причина: Обращение к нулевому указателю"
    else
        echo "Тип: MEMORY ACCESS VIOLATION"
        echo "Причина: Доступ к невалидному адресу памяти"
    fi
fi
