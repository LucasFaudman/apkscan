from yaml import safe_load as yaml_safe_load, YAMLError
from json import loads as json_loads, JSONDecodeError
from dataclasses import dataclass, field
from typing import Optional, Iterator, Literal, Generator
from pathlib import Path
from re import compile as re_compile, Pattern
import time
from pprint import pprint
from concurrent_executor import execute_concurrently, ConcurrentExecutor


@dataclass
class SecretLocator:
    name: str
    description: str = "No description provided."
    confidence: str = "Unknown"
    severity: str = "Unknown"
    patterns: set[Pattern] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)


    def __hash__(self) -> int:
        return hash(self.name)

@dataclass
class SecretResult:
    secret: str
    file: Path
    line_number: int
    matched_pattern: Pattern
    locator: SecretLocator

    def __hash__(self) -> int:
        return hash(self.secret + str(self.file) + str(self.line_number))


class SecretScanner:

    def __init__(self, 
                 secret_locator_files: list[Path],
                 load_locators_on_init: bool = True,
                 concurrency_type: Optional[Literal["thread", "process", "main", False]] = "thread",
                 results_order: Literal["completed", "submitted"] = "completed",
                 max_workers: Optional[int] = None,
                 save_results: bool = False,
                 ):
        self.secret_locators: dict[str, SecretLocator] = {}        
        self.load_locators_on_init = load_locators_on_init
        self.save_results = save_results
        self.results: dict[SecretLocator, list[SecretResult]] = {}

        self.concurrent_executor = ConcurrentExecutor(
            concurrency_type=concurrency_type,
            results_order=results_order,
            max_workers=max_workers
        )
        
        if load_locators_on_init:
            self.load_secret_locators(secret_locator_files)

    def _load_yaml_or_json(self, file_path: Path) -> Iterator[dict]:
        if not file_path.exists():
            print(f"File not found: {file_path}. Skipping.")
            return
        
        with file_path.open('r') as f:
            contents = f.read()

        try:
            yield from yaml_safe_load(contents)
        except (YAMLError, KeyError):
            print(f"Error loading {file_path} as YAML. Trying JSON.")
            try:
                yield from json_loads(contents)
            except (JSONDecodeError, KeyError):
                print(f"Error loading {file_path} as JSON (and YAML). Skipping.")


    def load_secret_locators(self, secret_locator_files: list[Path]) -> dict[str, SecretLocator]:
        for secret_locator_file in secret_locator_files:
            for locator_dict in self._load_yaml_or_json(secret_locator_file):
                pattern_bytes = [pattern_str.encode() for pattern_str in locator_dict['patterns']]
                locator_dict['patterns'] = set(map(re_compile, pattern_bytes))
                locator_dict['tags'] = set(locator_dict.get('tags', []))
                self.secret_locators[locator_dict['name']] = SecretLocator(**locator_dict)
        
        print(f"Loaded {len(self.secret_locators)} secret locators.\n")
        pprint(self.secret_locators)
        return self.secret_locators
                
    
    def iterscan_file(self, file_path: Path) -> Iterator[SecretResult]:
        print(f"\rScanning: {file_path.name}", end='')
        with file_path.open('rb') as f:
            for line_number, line in enumerate(f, start=1):
                for locator in self.secret_locators.values():
                    for pattern in locator.patterns:
                        if match := pattern.search(line):                            
                            secret_result = SecretResult(match.group(0).decode(), file_path, line_number, pattern, locator)                            
                            print(f"Found {locator.name}: {secret_result.secret} in {file_path.name} (line {line_number})")
                            yield secret_result
                            if self.save_results:
                                self.results.setdefault(locator, []).append(secret_result)



    def scan_file(self, file_path: Path) -> list[SecretResult]:
        return list(self.iterscan_file(file_path))
    
    def iterscan_files(self, file_paths: Iterator[Path]) -> Iterator[SecretResult]:
        for file_secret_results in self.concurrent_executor.map(self.scan_file, file_paths):
            yield from file_secret_results

    def scan_files(self, file_paths: Iterator[Path]) -> list[SecretResult]:
        return list(self.iterscan_files(file_paths))
    
    def iterscan_directory(self, directory_path: Path) -> Iterator[SecretResult]:
        yield from self.iterscan_files(filter(Path.is_file, directory_path.rglob("*")))

    def scan_directory(self, directory_path: Path) -> list[SecretResult]:
        return list(self.iterscan_directory(directory_path))
    
