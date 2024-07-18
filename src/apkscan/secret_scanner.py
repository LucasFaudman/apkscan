# © 2023 Lucas Faudman.
# Licensed under the MIT License (see LICENSE for details).
# For commercial use, see LICENSE for additional terms.
from dataclasses import dataclass, field
from typing import Optional, Iterator, Tuple
from pathlib import Path
from re import (
    compile as re_compile,
    Pattern,
    IGNORECASE,
    MULTILINE,
    DOTALL,
    ASCII,
    LOCALE,
    UNICODE,
    VERBOSE,
    TEMPLATE,
)

from yaml import safe_load as yaml_safe_load, YAMLError  # type: ignore
from json import loads as json_loads, JSONDecodeError

try:
    # Use built-in tomllib if python 3.11+ otherwise ignore TOML files
    from tomllib import loads as toml_loads, TOMLDecodeError

    TOML_SUPPORTED = True
except ImportError:
    print("tomllib not found. TOML files will be ignored. Use Python 3.11+ to enable TOML support.")
    TOML_SUPPORTED = False

from .concurrent_executor import ConcurrentExecutor
from .included_secret_locators import INCLUDED_SECRET_LOCATOR_FILES  # type: ignore


@dataclass
class SecretLocator:
    id: str
    name: str
    pattern: Pattern
    secret_group: int | str = 0
    description: Optional[str] = "No description provided."
    confidence: Optional[str] = "Unknown"
    severity: Optional[str] = "Unknown"
    tags: list[str] = field(default_factory=list)

    def __hash__(self) -> int:
        return hash(self.pattern)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretLocator):
            return NotImplemented
        return self.pattern == other.pattern


@dataclass
class SecretResult:
    secret: bytes
    file_path: Path
    line_number: int
    locator: SecretLocator

    def __hash__(self) -> int:
        return hash(self.secret)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretResult):
            return NotImplemented
        return self.secret == other.secret


def try_load_json_yaml_toml(file_path: Path) -> Optional[dict | list]:
    if not file_path.exists():
        print(f"File not found: {file_path}. Skipping.")
        return None

    with file_path.open("r") as f:
        contents = f.read()

    try:
        if (loaded_json := json_loads(contents)) and not isinstance(loaded_json, str):
            return loaded_json
    except JSONDecodeError:
        print(f"Error loading {file_path} as JSON. Trying YAML.")

    try:
        if (loaded_yaml := yaml_safe_load(contents)) and not isinstance(loaded_yaml, str):
            return loaded_yaml
    except YAMLError:
        print(f"Error loading {file_path} as YAML. Trying TOML.")

    if TOML_SUPPORTED:
        try:
            if (loaded_toml := toml_loads(contents)) and not isinstance(loaded_toml, str):
                return loaded_toml
        except TOMLDecodeError:
            print(f"Error loading {file_path} as TOML. Skipping.")

    return None


def compile_str_to_bytes_pattern(pattern_str: str) -> Pattern:
    flag_notation = {
        "i": IGNORECASE,
        "m": MULTILINE,
        "s": DOTALL,
        "a": ASCII,
        "l": LOCALE,
        "u": UNICODE,
        "x": VERBOSE,
        "t": TEMPLATE,
    }

    flags = 0
    for flag_char, flag in flag_notation.items():
        if f"(?{flag_char})" in pattern_str or f"(?-{flag_char})" in pattern_str:
            flags |= flag
            pattern_str = pattern_str.replace(
                f"(?{flag_char})",
                "",
            ).replace(f"(?-{flag_char})", "")
    return re_compile(pattern_str.encode(), flags)


def load_secrets_patterns_db_format(locator_dicts: list[dict]) -> dict[str, SecretLocator]:
    secret_locators: dict[str, SecretLocator] = {}
    for locator_dict in locator_dicts:
        locator_dict = locator_dict["pattern"]
        pattern_str = locator_dict.pop("regex")
        locator_dict["pattern"] = compile_str_to_bytes_pattern(pattern_str)
        locator_dict["id"] = locator_dict["name"].replace(" ", "-").lower()
        secret_locators[pattern_str] = SecretLocator(**locator_dict)

    return secret_locators


def load_gitleaks_format(locator_dicts: list[dict]) -> dict[str, SecretLocator]:
    secret_locators: dict[str, SecretLocator] = {}
    for locator_dict in locator_dicts:
        pattern_str = locator_dict.pop("regex")
        locator_dict["pattern"] = compile_str_to_bytes_pattern(pattern_str)
        locator_dict["name"] = locator_dict["id"].replace("-", " ").title()
        locator_dict["secret_group"] = locator_dict.pop("secretGroup", 0)
        locator_dict["tags"] = locator_dict.pop("keywords", [])
        locator_dict.pop("entropy", None)
        locator_dict.pop("allowlist", None)
        secret_locators[pattern_str] = SecretLocator(**locator_dict)

    return secret_locators


def load_secret_locators_format(locator_dicts: list[dict]) -> dict[str, SecretLocator]:
    secret_locators: dict[str, SecretLocator] = {}
    for locator_dict in locator_dicts:
        try:
            pattern_str = locator_dict.pop("pattern")
            locator_dict["pattern"] = compile_str_to_bytes_pattern(pattern_str)
            secret_locators[pattern_str] = SecretLocator(**locator_dict)
        except Exception as e:
            print(f"Error loading locator: {locator_dict}. Skipping. {e}")

    return secret_locators


def load_simple_key_value_format(simple_locator_dict: dict) -> dict[str, SecretLocator]:
    secret_locators: dict[str, SecretLocator] = {}
    for name, pattern_strs in simple_locator_dict.items():
        if isinstance(pattern_strs, str):
            pattern_strs = [pattern_strs]

        for i, pattern_str in enumerate(pattern_strs):
            locator_dict = {
                "id": name.replace(" ", "-").lower() + (f"-{i}" if i else ""),
                "name": name + (f" {i}" if i else ""),
                "pattern": compile_str_to_bytes_pattern(pattern_str),
            }
            secret_locators[pattern_str] = SecretLocator(**locator_dict)
    return secret_locators


def load_secret_locators(secret_locator_files: list[Path]) -> dict[str, SecretLocator]:
    print(f"\nLoading secret locators from {len(secret_locator_files)} files.")
    secret_locators: dict[str, SecretLocator] = {}
    for secret_locator_file in secret_locator_files:
        if not (secret_locator_file_data := try_load_json_yaml_toml(secret_locator_file)):
            continue
        if isinstance(secret_locator_file_data, list):
            secret_locators.update(load_secret_locators_format(secret_locator_file_data))
        elif locator_dicts := secret_locator_file_data.get("patterns"):
            secret_locators.update(load_secrets_patterns_db_format(locator_dicts))
        elif locator_dicts := secret_locator_file_data.get("rules"):
            secret_locators.update(load_gitleaks_format(locator_dicts))
        else:
            secret_locators.update(load_simple_key_value_format(secret_locator_file_data))

    print(f"\nLoaded {len(secret_locators)} secret locators.")
    return secret_locators


def find_secret_locator_files_by_name(secret_locator_files: list[Path]):
    existing = []
    for secret_locator_file in secret_locator_files:
        if secret_locator_file.exists():
            existing.append(secret_locator_file)
        elif secret_locator_file.stem in INCLUDED_SECRET_LOCATOR_FILES:
            existing.append(INCLUDED_SECRET_LOCATOR_FILES[secret_locator_file.stem])
    return existing


class SecretScanner:
    def __init__(
        self,
        **concurrent_executor_kwargs,
    ) -> None:
        self.secret_locator_files: list[Path] = []
        self.secret_locators: dict[str, SecretLocator] = {}
        self.results: dict[SecretLocator, list[SecretResult]] = {}
        self.concurrent_executor = ConcurrentExecutor(**{"concurrency_type": "process", **concurrent_executor_kwargs})

    def load_secret_locators(self, secret_locator_files: list[Path]) -> Tuple[dict[str, SecretLocator], list[Path]]:
        secret_locator_files = find_secret_locator_files_by_name(secret_locator_files)
        self.secret_locator_files.extend(secret_locator_files)
        self.secret_locators.update(load_secret_locators(secret_locator_files))
        return self.secret_locators, self.secret_locator_files

    def iterscan_file(self, file_path: Path) -> Iterator[SecretResult]:
        with file_path.open("rb") as f:
            for line_number, line in enumerate(f, start=1):
                for locator in self.secret_locators.values():
                    if match := locator.pattern.search(line):
                        yield SecretResult(
                            secret=match.group(locator.secret_group),
                            file_path=file_path,
                            line_number=line_number,
                            locator=locator,
                        )

    def scan_file(self, file_path: Path) -> tuple[Path, list[SecretResult]]:
        return file_path, list(self.iterscan_file(file_path))

    def scan_concurrently(self, file_paths: Iterator[Path]) -> Iterator[tuple[Path, list[SecretResult]]]:
        yield from self.concurrent_executor.map(self.scan_file, file_paths)

    def __repr__(self) -> str:
        return f"SecretScanner(secret_locators={len(self.secret_locators)}, concurrent_executor={self.concurrent_executor}))"
