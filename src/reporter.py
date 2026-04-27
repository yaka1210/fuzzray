# src/reporter.py
from pathlib import Path
from datetime import datetime
from typing import List
from jinja2 import Template
from rich.console import Console

from models import Crash

console = Console(highlight=True)

RECOMMENDATIONS = {
    "ProcessGpsInfo": "Проверьте границы буфера GPS (ByteCountUnused). Добавьте проверку длины перед доступом.",
    "Get32s": "Добавьте bounds check и NULL-проверку в EXIF-парсере.",
    "Get16u": "Добавьте проверку длины перед чтением 16-битных значений.",
    "ProcessExifDir": "Добавьте проверку OffsetBase и ExifLength — защита от NULL и OOB.",
    "strncpy_avx2": "Замените strncpy на strncpy_s или добавьте явную проверку длины.",
    "SIGSEGV": "Включите ASan/UBSan + добавьте bounds checking во всех парсерах.",
    "default": "Проведите статический анализ и добавьте границы + NULL-проверки в парсере."
}


def generate_recommendation(crash: Crash) -> str:
    """Генерация рекомендации по исправлению"""
    if not crash.gdb_analysis or not crash.gdb_analysis.function:
        return RECOMMENDATIONS["default"]

    func = crash.gdb_analysis.function or ""
    code = crash.code or ""

    for key in RECOMMENDATIONS:
        if key in func or key in code:
            return RECOMMENDATIONS[key]
    return RECOMMENDATIONS["default"]


def generate_html_report(
    stats: dict,
    prioritized: List[Crash],
    classified: dict,
    afl_stats: dict,
    output_path: str = "fuzzray_report.html"
):
    console.print("[cyan]→ Генерация финального стильного отчёта...[/cyan]")

    date_str = datetime.now().strftime("%d.%m.%Y %H:%M")

    for crash in prioritized:
        crash.recommendation = generate_recommendation(crash)

    level1 = [c for c in prioritized if c.level == "1"]
    level2 = [c for c in prioritized if c.level == "2" and c.code != "ERROR_TIMEOUT"]  # краши, без хэнгов
    hangs_count = len(classified.get("hangs", []))

    template = Template('''<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FuzzRay — Отчёт анализа AFL++</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <style>
        body {
            background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
            color: #e0e1dd;
            font-family: system-ui, sans-serif;
            min-height: 100vh;
            padding: 40px 20px;
        }
        .container {
            max-width: 1350px;
            margin: 0 auto;
            background: rgba(15, 12, 41, 0.95);
            backdrop-filter: blur(16px);
            border-radius: 28px;
            border: 1px solid rgba(100, 100, 255, 0.3);
            padding: 40px;
            box-shadow: 0 30px 80px rgba(0,0,0,0.7);
        }
        .header h1 {
            font-size: 3.8rem;
            background: linear-gradient(90deg, #00ddeb, #ff6ec7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 800;
            text-align: center;
        }
        .stat-box {
            background: rgba(30, 30, 80, 0.8);
            border-radius: 20px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(0, 221, 235, 0.5);
        }
        .stat-value { font-size: 2.8rem; font-weight: 800; color: #00ddeb; }
        .section {
            margin: 45px 0;
            padding: 35px;
            border-radius: 20px;
            background: rgba(20, 20, 60, 0.8);
            border-left: 8px solid;
        }
        .section.critical { border-left-color: #ff4757; }
        .section.errors   { border-left-color: #ffa502; }
        .section.hangs    { border-left-color: #00ddeb; }
        .accordion-button {
            background: rgba(40, 40, 100, 0.9) !important;
            color: #ffffff !important;
            font-weight: 600;
        }
        .accordion-body {
            background: #0a0f24 !important;
            color: #ffffff !important;
            line-height: 1.65;
        }
        .crash-title {
            color: #ffffff !important;
            font-size: 1.35rem;
            font-weight: 700;
            margin-bottom: 15px;
        }
        .crash-info strong {
            color: #00f0ff !important;
        }
        .recommendation {
            background: rgba(255, 204, 102, 0.1);
            padding: 15px;
            border-radius: 10px;
            margin: 18px 0;
        }
        pre {
            background: #0a0f1f;
            color: #a0d6ff;
            padding: 18px;
            border-radius: 10px;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 520px;
            overflow-y: auto;
            border: 1px solid rgba(0, 221, 235, 0.4);
        }
        .empty { color: #8899bb; font-style: italic; text-align: center; padding: 60px 20px; }
        .footer { text-align: center; margin-top: 70px; color: #8899bb; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>FuzzRay</h1>
            <p class="subtitle">Анализ результатов AFL++ • {{ date }}</p>
        </div>

        <!-- Статистика -->
        <div class="row g-4 mb-5">
            <div class="col-md-3">
                <div class="stat-box">
                    <div class="stat-value">{{ stats.total }}</div>
                    <div>Всего крашей</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-box">
                    <div class="stat-value">{{ stats.unique_locations }}</div>
                    <div>Уникальных мест</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-box">
                    <div class="stat-value">{{ stats.duplicates_removed }}</div>
                    <div>Удалено дубликатов</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-box">
                    <div class="stat-value">{{ hangs_count }}</div>
                    <div>Хэнгов</div>
                </div>
            </div>
        </div>

        <!-- Level 2: Ошибки выполнения -->
        <div class="section errors">
            <h2 class="section-title"><i class="bi bi-exclamation-triangle-fill me-2"></i>Ошибки выполнения (Level 2)</h2>
            {% if level2 %}
                <div class="accordion" id="level2">
                    {% for i, crash in level2 %}
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#l2{{ i }}">
                                {{ crash.file }} • {{ crash.manifestations }} проявлений
                                <span class="badge bg-warning text-dark ms-3">{{ crash.priority }}</span>
                            </button>
                        </h2>
                        <div id="l2{{ i }}" class="accordion-collapse collapse">
                            <div class="accordion-body">
                                <div class="crash-title">{{ crash.file }}</div>
                                <div class="crash-info"><strong>Функция:</strong> {{ crash.gdb_analysis.function|default('—') if crash.gdb_analysis else '—' }}</div>
                                <div class="crash-info"><strong>Место:</strong> {{ (crash.gdb_analysis.source_file|default('—')) if crash.gdb_analysis else '—' }}:{{ (crash.gdb_analysis.source_line|default('—')) if crash.gdb_analysis else '—' }}</div>
                                <div class="recommendation">
                                    <strong>Рекомендация по исправлению:</strong><br>
                                    <em>{{ crash.recommendation|default('—') }}</em>
                                </div>
                                <strong>Backtrace:</strong>
                                <pre>{{ (crash.gdb_analysis.backtrace|join('\n')) if crash.gdb_analysis and crash.gdb_analysis.backtrace else 'Нет данных' }}</pre>
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            {% else %}
                <p class="empty">Ошибок выполнения (Level 2) не найдено</p>
            {% endif %}
        </div>

        <!-- Level 1: Критические уязвимости -->
        <div class="section critical">
            <h2 class="section-title"><i class="bi bi-bug-fill me-2"></i>Критические уязвимости (CWE Level 1)</h2>
            {% if level1 %}
                <div class="accordion" id="level1">
                    {% for i, crash in level1 %}
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#l1{{ i }}">
                                {{ crash.file }} • {{ crash.manifestations }} проявлений
                                <span class="badge bg-danger ms-3">{{ crash.priority }}</span>
                            </button>
                        </h2>
                        <div id="l1{{ i }}" class="accordion-collapse collapse">
                            <div class="accordion-body">
                                <div class="crash-title">{{ crash.file }}</div>
                                <div class="crash-info"><strong>Функция:</strong> {{ crash.gdb_analysis.function|default('—') if crash.gdb_analysis else '—' }}</div>
                                <div class="crash-info"><strong>Место:</strong> {{ (crash.gdb_analysis.source_file|default('—')) if crash.gdb_analysis else '—' }}:{{ (crash.gdb_analysis.source_line|default('—')) if crash.gdb_analysis else '—' }}</div>
                                <div class="recommendation">
                                    <strong>Рекомендация по исправлению:</strong><br>
                                    <em>{{ crash.recommendation|default('—') }}</em>
                                </div>
                                <strong>Backtrace:</strong>
                                <pre>{{ (crash.gdb_analysis.backtrace|join('\n')) if crash.gdb_analysis and crash.gdb_analysis.backtrace else 'Нет данных' }}</pre>
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            {% else %}
                <p class="empty">Критических уязвимостей (CWE Level 1) не найдено</p>
            {% endif %}
        </div>

        <!-- Hangs -->
        <div class="section hangs">
            <h2 class="section-title"><i class="bi bi-hourglass-split me-2"></i>Зависания (Hangs)</h2>
            {% if hangs_count > 0 %}
                <p class="fs-5">Найдено {{ hangs_count }} зависаний</p>
            {% else %}
                <p class="empty">Зависаний не найдено</p>
            {% endif %}
        </div>

        <div class="footer">
            Сгенерировано автоматически инструментом <strong>FuzzRay</strong> • {{ date }}
        </div>
    </div>
</body>
</html>''')

    # Рендеринг
    html = template.render(
        date=date_str,
        stats=stats,
        level1=enumerate([c.to_dict() for c in level1]),
        level2=enumerate([c.to_dict() for c in level2]),
        hangs_count=hangs_count,
        afl=afl_stats
    )

    Path(output_path).write_text(html, encoding="utf-8")
    console.print(f"[green]✓ Отчёт успешно создан: {output_path}[/green]")