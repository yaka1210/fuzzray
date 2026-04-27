#!/bin/bash

echo "=== ПОЛНЫЙ АНАЛИЗ КРАШЕЙ AFL++ ==="
echo ""

# Проверяем наличие крашей
CRASH_DIR="results/default/crashes.2025-12-04-01:52:37"
if [ ! -d "$CRASH_DIR" ]; then
    echo "❌ Директория крашей не найдена!"
    exit 1
fi

# Считаем краши
TOTAL_CRASHES=$(ls "$CRASH_DIR" | wc -l)
echo "Всего найдено крашей: $TOTAL_CRASHES"
echo ""

# 1. Анализируем сигналы
echo "📊 АНАЛИЗ СИГНАЛОВ:"
echo "-----------------"
for crash in "$CRASH_DIR"/id*; do
    if [ -f "$crash" ]; then
        # Извлекаем сигнал из имени файла
        SIG=$(echo "$crash" | grep -o 'sig:[0-9]*' | cut -d: -f2)
        
        case $SIG in
            11)
                echo "$(basename "$crash") - SIGSEGV (Segmentation Fault)"
                echo "   ↳ Переполнение буфера, доступ к невалидной памяти"
                ;;
            06)
                echo "$(basename "$crash") - SIGABRT (Abort)"
                echo "   ↳ Обычно от AddressSanitizer: heap corruption"
                ;;
            07)
                echo "$(basename "$crash") - SIGBUS (Bus Error)"
                echo "   ↳ Ошибка выравнивания памяти"
                ;;
            04)
                echo "$(basename "$crash") - SIGILL (Illegal Instruction)"
                echo "   ↳ Поврежденный машинный код"
                ;;
            08)
                echo "$(basename "$crash") - SIGFPE (Floating Point)"
                echo "   ↳ Деление на ноль, переполнение float"
                ;;
            *)
                echo "$(basename "$crash") - Неизвестный сигнал $SIG"
                ;;
        esac
    fi
done | sort

echo ""
echo "🔍 АНАЛИЗ КАЖДОГО КРАША:"
echo "----------------------"

# 2. Детальный анализ каждого краша
COUNTER=1
for crash in "$CRASH_DIR"/id*; do
    if [ ! -f "$crash" ]; then
        continue
    fi
    
    echo ""
    echo "🛑 КРАШ #$COUNTER: $(basename "$crash")"
    echo "   Размер файла: $(stat -c%s "$crash") байт"
    
    # Определяем тип данных
    echo -n "   Тип данных: "
    if file "$crash" | grep -q "JPEG"; then
        echo "JPEG изображение"
    elif file "$crash" | grep -q "ASCII"; then
        echo "Текстовый файл"
    elif file "$crash" | grep -q "data"; then
        echo "Бинарные данные"
    else
        echo "Не определен"
    fi
    
    # Проверяем наличие JPEG заголовка
    if head -c 4 "$crash" | xxd | grep -q "ff d8"; then
        echo "   ✓ Имеет JPEG заголовок (FF D8)"
    fi
    
    # Быстрая проверка воспроизведения
    echo -n "   Тест воспроизведения: "
    timeout 2 ./jhead "$crash" 2>&1 | grep -q "Segmentation fault" && echo "✅ Падает" || echo "⚠️ Требует проверки"
    
    COUNTER=$((COUNTER + 1))
done

echo ""
echo "📈 СВОДКА:"
echo "---------"
echo "Всего SIGSEGV (11): $(ls "$CRASH_DIR"/*sig:11* 2>/dev/null | wc -l)"
echo "Всего SIGABRT (06): $(ls "$CRASH_DIR"/*sig:06* 2>/dev/null | wc -l)"
echo "Всего других сигналов: $(ls "$CRASH_DIR"/* | grep -v 'sig:11' | grep -v 'sig:06' | wc -l)"
