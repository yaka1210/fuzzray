#!/bin/bash

echo "=== ГРУППИРОВКА ПОХОЖИХ КРАШЕЙ ==="
echo ""

CRASH_DIR="results/default/crashes"
mkdir -p grouped_crashes

# Группируем по сигналу
echo "1. Группировка по сигналам:"
for sig in 11 06 07 04 08; do
    count=$(ls "$CRASH_DIR"/*sig:${sig}* 2>/dev/null | wc -l)
    if [ $count -gt 0 ]; then
        echo "  SIG $sig: $count крашей"
        mkdir -p "grouped_crashes/sig_${sig}"
        cp "$CRASH_DIR"/*sig:${sig}* "grouped_crashes/sig_${sig}/" 2>/dev/null
    fi
done

# Группируем по размеру
echo ""
echo "2. Группировка по размеру:"
small=0; medium=0; large=0
for crash in "$CRASH_DIR"/id*; do
    size=$(stat -c%s "$crash" 2>/dev/null || echo 0)
    if [ $size -lt 100 ]; then
        ((small++))
    elif [ $size -lt 1000 ]; then
        ((medium++))
    else
        ((large++))
    fi
done

echo "  Малые (<100 байт): $small"
echo "  Средние (100-1000): $medium"
echo "  Большие (>1000): $large"

# Создаем отчет
echo ""
echo "3. СОЗДАНИЕ ОТЧЕТА:"
cat > crash_report.txt << EOF
ОТЧЕТ О КРАШАХ AFL++
Дата: $(date)
Программа: jhead 2.90
Всего крашей: $(ls "$CRASH_DIR" | wc -l)

РАСПРЕДЕЛЕНИЕ ПО СИГНАЛАМ:
SIGSEGV (11):  $(ls "$CRASH_DIR"/*sig:11* 2>/dev/null | wc -l)
SIGABRT (06):  $(ls "$CRASH_DIR"/*sig:06* 2>/dev/null | wc -l)
SIGBUS (07):   $(ls "$CRASH_DIR"/*sig:07* 2>/dev/null | wc -l)
SIGILL (04):   $(ls "$CRASH_DIR"/*sig:04* 2>/dev/null | wc -l)
SIGFPE (08):   $(ls "$CRASH_DIR"/*sig:08* 2>/dev/null | wc -l)

РАСПРЕДЕЛЕНИЕ ПО РАЗМЕРУ:
Малые (<100 байт):   $small
Средние (100-1000):  $medium
Большие (>1000):     $large

ДЕТАЛИ КРАШЕЙ:
$(for crash in "$CRASH_DIR"/id*; do
  echo "- $(basename "$crash"): $(stat -c%s "$crash") байт"
done)

РЕКОМЕНДАЦИИ:
1. Проанализировать SIGSEGV краши - вероятно переполнения буфера
2. Проверить обработку больших файлов
3. Добавить проверки границ при чтении JPEG
EOF

echo "Отчет сохранен в crash_report.txt"
