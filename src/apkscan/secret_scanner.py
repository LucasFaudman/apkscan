# © 2023 Lucas Faudman.
# Licensed under the MIT License (see LICENSE for details).
# For commercial use, see LICENSE for additional terms.
from yaml import safe_load as yaml_safe_load, YAMLError
from json import loads as json_loads, JSONDecodeError
from tomllib import loads as toml_loads, TOMLDecodeError
from dataclasses import dataclass, field
from typing import Optional, Iterator
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

from .concurrent_executor import ConcurrentExecutor

@dataclass
class SecretLocator:
    id: str
    name: str
    pattern: Pattern
    secret_group: int | str = 0
    description: str = "No description provided."
    confidence: str = "Unknown"
    severity: str = "Unknown"
    tags: list[str] = field(default_factory=list)

    def __hash__(self) -> int:
        return hash(self.pattern)

@dataclass
class SecretResult:
    secret: bytes
    file_path: Path
    line_number: int
    locator: SecretLocator

    def __hash__(self) -> int:
        return hash(self.secret)


def try_load_json_toml_yaml(file_path: Path) -> Optional[dict]:
    if not file_path.exists():
        print(f"File not found: {file_path}. Skipping.")
        return

    with file_path.open("r") as f:
        contents = f.read()

    try:
        return json_loads(contents)
    except JSONDecodeError:
        print(f"Error loading {file_path} as JSON. Trying TOML.")

    try:
        return toml_loads(contents)
    except TOMLDecodeError:
        print(f"Error loading {file_path} as TOML. Trying YAML.")

    try:
        return yaml_safe_load(contents)
    except YAMLError:
        print(f"Error loading {file_path} as YAML. Skipping.")


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
    secret_locators = {}
    for locator_dict in locator_dicts:
        locator_dict = locator_dict["pattern"]
        pattern_str = locator_dict.pop("regex")
        locator_dict["pattern"] = compile_str_to_bytes_pattern(pattern_str)
        locator_dict["id"] = locator_dict["name"].replace(" ", "-").lower()
        secret_locators[pattern_str] = SecretLocator(**locator_dict)

    return secret_locators

def load_gitleaks_format(locator_dicts: list[dict]) -> dict[str, SecretLocator]:
    secret_locators = {}
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
    secret_locators = {}
    for locator_dict in locator_dicts:
        pattern_str = locator_dict.pop("pattern")
        locator_dict["pattern"] = compile_str_to_bytes_pattern(pattern_str)
        secret_locators[pattern_str] = SecretLocator(**locator_dict)
    return secret_locators

def load_simple_key_value_format(simple_locator_dict: dict) -> dict[str, SecretLocator]:
    secret_locators = {}
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
        if not (secret_locator_file_data := try_load_json_toml_yaml(secret_locator_file)):
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


class SecretScanner:
    def __init__(
        self,
        secret_locator_files: list[Path],
        load_locators_on_init: bool = True,
        **concurrent_executor_kwargs,
    ):
        self.secret_locators: dict[str, SecretLocator] = {}
        self.load_locators_on_init = load_locators_on_init
        self.results: dict[SecretLocator, list[SecretResult]] = {}
        self.concurrent_executor = ConcurrentExecutor(**{"concurrency_type": "process", **concurrent_executor_kwargs})

        self.secret_locator_files = []
        if load_locators_on_init:
            self.load_secret_locators(secret_locator_files)

    def load_secret_locators(self, secret_locator_files: list[Path]) -> dict[str, SecretLocator]:
        self.secret_locator_files.extend(secret_locator_files)
        self.secret_locators.update(load_secret_locators(secret_locator_files))
        return self.secret_locators

    def iterscan_file(self, file_path: Path) -> Iterator[SecretResult]:
        with file_path.open("rb") as f:
            for line_number, line in enumerate(f, start=1):
                for locator in self.secret_locators.values():
                    if match := locator.pattern.search(line):
                        yield SecretResult(
                            secret=match.group(locator.secret_group),
                            file_path=file_path,
                            line_number=line_number,
                            locator=locator)

    def scan_file(self, file_path: Path) -> tuple[Path, list[SecretResult]]:
        return file_path, list(self.iterscan_file(file_path))

    def scan_concurrently(self, file_paths: Iterator[Path]) -> Iterator[tuple[Path, list[SecretResult]]]:
        yield from self.concurrent_executor.map(self.scan_file, file_paths)

    def __repr__(self) -> str:
        return f"SecretScanner(secret_locators={len(self.secret_locators)}, concurrent_executor={self.concurrent_executor}))"
