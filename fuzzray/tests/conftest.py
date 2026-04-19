from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def afl_out(tmp_path: Path) -> Path:
    inst = tmp_path / "fuzzer01"
    (inst / "crashes").mkdir(parents=True)
    (inst / "queue").mkdir()
    (inst / "crashes" / "id:000000,sig:11,src:000000,op:havoc,rep:4").write_bytes(b"AAAA" * 4)
    (inst / "crashes" / "id:000001,sig:11,src:000000,op:havoc,rep:2").write_bytes(b"BBBB" * 4)
    (inst / "crashes" / "id:000002,sig:06,src:000001,op:havoc,rep:1").write_bytes(b"CCCC" * 4)
    (inst / "crashes" / "id:000003,sig:08,src:000002,op:havoc,rep:1").write_bytes(b"DDDD" * 4)
    (inst / "crashes" / "id:000004,sig:11,src:000000,op:havoc,rep:4").write_bytes(b"AAAA" * 4)
    (inst / "crashes" / "README.txt").write_text("ignored")

    (inst / "fuzzer_stats").write_text(
        "start_time        : 1700000000\n"
        "last_update       : 1700000600\n"
        "execs_done        : 123456\n"
        "execs_per_sec     : 2048.5\n"
        "corpus_count      : 42\n"
        "saved_crashes     : 5\n"
        "saved_hangs       : 0\n"
        "afl_version       : ++4.21c\n"
        "command_line      : afl-fuzz -i in -o out -- ./target @@\n"
    )
    (inst / "plot_data").write_text(
        "# unix_time, cycles_done, cur_item, corpus_count, pending_total, pending_favs, map_size, saved_crashes, saved_hangs, max_depth, execs_per_sec\n"
        "1700000000, 0, 0, 1, 1, 1, 10.00%, 0, 0, 1, 0.0\n"
        "1700000300, 1, 5, 20, 10, 3, 30.00%, 2, 0, 3, 1500.0\n"
        "1700000600, 2, 9, 42, 12, 4, 45.00%, 5, 0, 5, 2048.5\n"
    )
    return tmp_path
