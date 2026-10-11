from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path


def create_candidate_run_dirs(root: str | Path, task: str) -> tuple[Path, Path]:
    root_path = Path(root)
    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    model_dir = root_path / "models" / "candidates" / task / run_id
    report_dir = root_path / "reports" / "candidates" / task / run_id
    model_dir.mkdir(parents=True, exist_ok=False)
    report_dir.mkdir(parents=True, exist_ok=False)
    return model_dir, report_dir
