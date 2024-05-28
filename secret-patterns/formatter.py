from yaml import safe_load, safe_dump
from pathlib import Path

with (Path(__file__).parent / "all.yaml").open() as f:
    data = safe_load(f)
    print(data)
