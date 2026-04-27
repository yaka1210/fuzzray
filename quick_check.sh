#!/bin/bash
echo "=== БЫСТРАЯ ПРОВЕРКА КРАШЕЙ ==="
echo ""
for crash in results/default/crashes.2025-12-04-01:52:37/id*sig:11*; do
    echo "📄 $(basename "$crash")"
    echo "   Размер: $(stat -c%s "$crash")"
    echo -n "   Тест: "
    timeout 1 ./jhead "$crash" 2>&1 | grep -q "fault" && echo "✅ Падает" || echo "❓"
    echo "   Начало: $(hexdump -C -n 16 "$crash" | tail -1)"
    echo ""
done
