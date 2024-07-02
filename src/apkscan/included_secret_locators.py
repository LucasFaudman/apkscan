# © 2023 Lucas Faudman.
# Licensed under the MIT License (see LICENSE for details).
# For commercial use, see LICENSE for additional terms.
from pathlib import Path

# Defined outside of secret_scanner.py so not broken by mypyc since using __file__
INCLUDED_SECRET_LOCATOR_FILES = {path.stem: path for path in (Path(__file__).parent / "secret_locators").rglob("*")}
