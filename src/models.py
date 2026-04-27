# src/models.py
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from pathlib import Path


@dataclass
class GDBAnalysis:
    """Результат анализа краша через GDB"""
    success: bool = False
    signal: Optional[str] = None
    function: Optional[str] = None
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    crash_address: Optional[str] = None
    backtrace: List[str] = field(default_factory=list)
    registers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class Crash:
    """Единая модель краша во всём проекте"""
    file: str
    path: str
    level: str = "Unknown"
    code: str = "ERROR_UNKNOWN"
    description: str = "Неизвестный тип ошибки"
    manifestations: int = 1
    priority: str = "Низкий"
    recommendation: str = "—"                    # ← Добавлено
    gdb_analysis: Optional[GDBAnalysis] = None   # ← Критично для backtrace

    @property
    def is_critical(self) -> bool:
        return self.level == "1"

    @property
    def is_error(self) -> bool:
        return self.level == "2"

    def to_dict(self) -> Dict[str, Any]:
        """Для совместимости с Jinja2 и отчётом"""
        gdb_dict = None
        if self.gdb_analysis:
            gdb_dict = {
                "success": self.gdb_analysis.success,
                "signal": self.gdb_analysis.signal,
                "function": self.gdb_analysis.function,
                "source_file": self.gdb_analysis.source_file,
                "source_line": self.gdb_analysis.source_line,
                "crash_address": self.gdb_analysis.crash_address,
                "backtrace": self.gdb_analysis.backtrace,
                "registers": self.gdb_analysis.registers,
                "error": self.gdb_analysis.error,
            }

        return {
            "file": self.file,
            "path": self.path,
            "level": self.level,
            "code": self.code,
            "description": self.description,
            "manifestations": self.manifestations,
            "priority": self.priority,
            "recommendation": self.recommendation,
            "gdb_analysis": gdb_dict
        }


def crash_from_dict(data: Dict) -> Crash:
    """Вспомогательная функция (на всякий случай)"""
    gdb_data = data.get("gdb_analysis")
    gdb = None
    if isinstance(gdb_data, dict):
        gdb = GDBAnalysis(
            success=gdb_data.get("success", False),
            signal=gdb_data.get("signal"),
            function=gdb_data.get("function"),
            source_file=gdb_data.get("source_file"),
            source_line=gdb_data.get("source_line"),
            crash_address=gdb_data.get("crash_address"),
            backtrace=gdb_data.get("backtrace", []),
            registers=gdb_data.get("registers", {}),
            error=gdb_data.get("error")
        )

    return Crash(
        file=data.get("file", ""),
        path=data.get("path", ""),
        level=data.get("level", "Unknown"),
        code=data.get("code", "ERROR_UNKNOWN"),
        description=data.get("description", ""),
        manifestations=data.get("manifestations", 1),
        priority=data.get("priority", "Низкий"),
        recommendation=data.get("recommendation", "—"),
        gdb_analysis=gdb
    )