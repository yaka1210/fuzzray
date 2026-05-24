from __future__ import annotations

import multiprocessing
import threading
import webbrowser
from pathlib import Path

import customtkinter as ctk
from tkinter import filedialog, messagebox


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class _GuiWriter:
    def __init__(self, callback: object) -> None:
        self._cb = callback

    def write(self, text: str) -> None:
        if text:
            self._cb(text)  # type: ignore[call-arg]

    def flush(self) -> None:
        pass


class FuzzRayApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("FuzzRay")
        self.geometry("680x620")
        self.resizable(False, False)
        self._build_ui()

    def _build_ui(self) -> None:
        # Title
        ctk.CTkLabel(
            self, text="FuzzRay", font=ctk.CTkFont(size=22, weight="bold")
        ).grid(row=0, column=0, columnspan=3, pady=(18, 4))

        ctk.CTkLabel(
            self, text="Постпроцессор результатов AFL++",
            font=ctk.CTkFont(size=12), text_color="gray"
        ).grid(row=1, column=0, columnspan=3, pady=(0, 16))

        pad = {"padx": 16, "pady": 5}

        # AFL++ dir
        ctk.CTkLabel(self, text="Каталог AFL++ (--afl-out)", anchor="w").grid(
            row=2, column=0, sticky="w", **pad)
        self.afl_out_var = ctk.StringVar()
        ctk.CTkEntry(self, textvariable=self.afl_out_var, width=420).grid(
            row=3, column=0, columnspan=2, sticky="w", padx=16, pady=2)
        ctk.CTkButton(self, text="Обзор…", width=90, command=self._browse_afl).grid(
            row=3, column=2, padx=(4, 16), pady=2)

        # Output HTML
        ctk.CTkLabel(self, text="HTML-отчёт (-o)", anchor="w").grid(
            row=4, column=0, sticky="w", **pad)
        self.output_var = ctk.StringVar(value="fuzzray_report.html")
        ctk.CTkEntry(self, textvariable=self.output_var, width=420).grid(
            row=5, column=0, columnspan=2, sticky="w", padx=16, pady=2)
        ctk.CTkButton(self, text="Обзор…", width=90, command=self._browse_output).grid(
            row=5, column=2, padx=(4, 16), pady=2)

        # Target binary
        ctk.CTkLabel(self, text="Целевой бинарный файл (--target, необяз.)", anchor="w").grid(
            row=6, column=0, sticky="w", **pad)
        self.target_var = ctk.StringVar()
        ctk.CTkEntry(self, textvariable=self.target_var, width=420).grid(
            row=7, column=0, columnspan=2, sticky="w", padx=16, pady=2)
        ctk.CTkButton(self, text="Обзор…", width=90, command=self._browse_target).grid(
            row=7, column=2, padx=(4, 16), pady=2)

        # Options
        self.no_replay_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            self, text="Без GDB-воспроизведения (--no-replay)",
            variable=self.no_replay_var
        ).grid(row=8, column=0, columnspan=3, sticky="w", padx=16, pady=(12, 2))

        self.no_repro_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            self, text="Не генерировать скрипты репродьюсеров (--no-reproducers)",
            variable=self.no_repro_var
        ).grid(row=9, column=0, columnspan=3, sticky="w", padx=16, pady=(2, 12))

        # Progress bar
        self.progress = ctk.CTkProgressBar(self, width=620, mode="indeterminate")
        self.progress.grid(row=10, column=0, columnspan=3, padx=16, pady=(0, 4))
        self.progress.set(0)

        # Run button
        self.run_btn = ctk.CTkButton(
            self, text="▶  Запустить анализ",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=42, width=300,
            command=self._run,
        )
        self.run_btn.grid(row=11, column=0, columnspan=3, pady=10)

        # Log
        self.log = ctk.CTkTextbox(self, width=648, height=180, state="disabled",
                                   font=ctk.CTkFont(family="Courier", size=11))
        self.log.grid(row=12, column=0, columnspan=3, padx=16, pady=(0, 8))

        # Open report button
        self.open_btn = ctk.CTkButton(
            self, text="Открыть отчёт", width=200,
            state="disabled", command=self._open_report,
            fg_color="gray30", hover_color="gray40",
        )
        self.open_btn.grid(row=13, column=0, columnspan=3, pady=(0, 16))

    def _browse_afl(self) -> None:
        d = filedialog.askdirectory(title="Выберите каталог AFL++")
        if d:
            self.afl_out_var.set(d)
            if not self.output_var.get() or self.output_var.get() == "fuzzray_report.html":
                self.output_var.set(str(Path(d).parent / "fuzzray_report.html"))

    def _browse_output(self) -> None:
        f = filedialog.asksaveasfilename(
            title="Путь к HTML-отчёту",
            defaultextension=".html",
            filetypes=[("HTML", "*.html")],
        )
        if f:
            self.output_var.set(f)

    def _browse_target(self) -> None:
        f = filedialog.askopenfilename(title="Целевой бинарный файл")
        if f:
            self.target_var.set(f)

    def _log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _run(self) -> None:
        afl_out = self.afl_out_var.get().strip()
        if not afl_out:
            messagebox.showerror("Ошибка", "Укажите каталог AFL++")
            return
        if not Path(afl_out).exists():
            messagebox.showerror("Ошибка", f"Каталог не найден:\n{afl_out}")
            return

        self.run_btn.configure(state="disabled")
        self.open_btn.configure(state="disabled", fg_color="gray30")
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        self.progress.start()

        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self) -> None:
        from rich.console import Console
        import fuzzray.pipeline as pipeline_mod

        writer = _GuiWriter(lambda t: self.after(0, self._log, t))
        old_console = pipeline_mod.console
        pipeline_mod.console = Console(file=writer, highlight=False, no_color=True, width=80)  # type: ignore[assignment]

        target_str = self.target_var.get().strip()
        try:
            pipeline_mod.run_pipeline(
                afl_out=Path(self.afl_out_var.get()),
                output=Path(self.output_var.get()),
                target=Path(target_str) if target_str else None,
                target_args="@@",
                no_replay=self.no_replay_var.get(),
                jobs=0,
                do_minimize=False,
                write_reproducers=not self.no_repro_var.get(),
            )
            self.after(0, self._on_done, True)
        except Exception as exc:
            self.after(0, self._log, f"\nОшибка: {exc}\n")
            self.after(0, self._on_done, False)
        finally:
            pipeline_mod.console = old_console

    def _on_done(self, success: bool) -> None:
        self.progress.stop()
        self.progress.set(0)
        self.run_btn.configure(state="normal")
        if success:
            self.open_btn.configure(state="normal", fg_color=("#2563eb", "#1d4ed8"))
            self._log("\n✓ Готово. Отчёт сохранён.\n")
        else:
            self._log("\n✗ Завершено с ошибкой.\n")

    def _open_report(self) -> None:
        path = Path(self.output_var.get())
        if path.exists():
            webbrowser.open(path.resolve().as_uri())
        else:
            messagebox.showerror("Ошибка", f"Файл не найден:\n{path}")


def main() -> None:
    multiprocessing.freeze_support()
    app = FuzzRayApp()
    app.mainloop()


if __name__ == "__main__":
    main()
