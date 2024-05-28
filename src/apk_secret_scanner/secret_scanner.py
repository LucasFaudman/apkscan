from yaml import safe_load as yaml_safe_load, YAMLError
from json import loads as json_loads, JSONDecodeError
from tomllib import loads as toml_loads, TOMLDecodeError
from dataclasses import dataclass, field
from typing import Optional, Iterator, Literal, Generator
from pathlib import Path
from re import compile as re_compile, Pattern, Match
import time
from pprint import pprint
from concurrent_executor import ConcurrentExecutor


@dataclass
class SecretLocator:
    name: str
    description: str = "No description provided."
    confidence: str = "Unknown"
    severity: str = "Unknown"
    patterns: set[Pattern] = field(default_factory=set)
    secret_group: int|str = 0
    tags: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)

    def __hash__(self) -> int:
        return hash(self.name)

@dataclass
class SecretResult:
    secret: bytes
    file_path: Path
    line_number: int
    matched_pattern: Pattern
    locator: SecretLocator

    def __hash__(self) -> int:
        return hash(self.secret)


class SecretScanner:

    def __init__(self, 
                 secret_locator_files: list[Path],
                 load_locators_on_init: bool = True,
                 save_results: bool = False,
                 **concurrent_executor_kwargs
                 ):
        self.secret_locators: dict[str, SecretLocator] = {}        
        self.load_locators_on_init = load_locators_on_init
        self.save_results = save_results
        self.results: dict[SecretLocator, list[SecretResult]] = {}

        self.concurrent_executor = ConcurrentExecutor(
            **{'concurrency_type': 'process', **concurrent_executor_kwargs}
        )
        
        if load_locators_on_init:
            self.load_secret_locators(secret_locator_files)

    def try_load_yaml_toml_or_json(self, file_path: Path) -> Optional[dict]:
        if not file_path.exists():
            print(f"File not found: {file_path}. Skipping.")
            return
        
        with file_path.open('r') as f:
            contents = f.read()

        try:
            return yaml_safe_load(contents)
        except (YAMLError, KeyError):
            print(f"Error loading {file_path} as YAML. Trying TOML.")
        
        try:
            return toml_loads(contents)
        except (TOMLDecodeError, KeyError):
            print(f"Error loading {file_path} as TOML. Trying JSON.")

        try:
            return json_loads(contents)
        except (JSONDecodeError, KeyError):
            print(f"Error loading {file_path} as JSON. Skipping.")

    def make_secret_locator(self, locator_dict: dict) -> SecretLocator:
        pattern_strs = locator_dict.get('patterns') or (locator_dict.pop('regex'),)
        pattern_bytes = [pattern_str.encode() for pattern_str in pattern_strs]
        locator_dict['patterns'] = set(map(re_compile, pattern_bytes))
        if locator_id := locator_dict.pop('id', None):
            locator_dict['name'] = locator_id
        return SecretLocator(**locator_dict)
    
    def load_secrets_patterns_db_format(self, secret_locator_file_data: dict) -> dict[str, SecretLocator]:
        return {locator_dict['pattern']['name']: self.make_secret_locator(locator_dict['pattern'])
                for locator_dict in secret_locator_file_data['patterns']}
    
    def load_gitleaks_format(self, secret_locator_file_data: dict) -> dict[str, SecretLocator]:
        return {locator_dict['id']: self.make_secret_locator(locator_dict)
                for locator_dict in secret_locator_file_data['rules']}

    def load_secret_locators(self, secret_locator_files: list[Path]) -> dict[str, SecretLocator]:
        for secret_locator_file in secret_locator_files:
            if not (secret_locator_file_data := self.try_load_yaml_toml_or_json(secret_locator_file)):
                continue
            if secret_locators := self.load_secrets_patterns_db_format(secret_locator_file_data):
                self.secret_locators.update(secret_locators)
            elif secret_locators := self.load_gitleaks_format(secret_locator_file_data):
                self.secret_locators.update(secret_locators)

        print(f"\nLoaded {len(self.secret_locators)} secret locators.")
        return self.secret_locators
    
    def iterscan_file(self, file_path: Path) -> Iterator[SecretResult]:
        print(f'Scanning: {file_path.name} ', end='\r')
        with file_path.open('rb') as f:
            for line_number, line in enumerate(f, start=1):
                for locator in self.secret_locators.values():
                    for pattern in locator.patterns:
                        if match := pattern.search(line):                            
                            secret_result = SecretResult(match.group(locator.secret_group), file_path, line_number, pattern, locator)                                                        
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
    
if __name__ == '__main__':
    start = time.time()
    scanner = SecretScanner([Path(__file__).parent.parent.parent / 'secret-patterns/high-confidence.yml'],
                            concurrency_type='process',
                            # max_workers=20,
                            chunksize=1,
                            )
    results = set()
    for secret_result in scanner.iterscan_directory(Path('testoutput/')):
        print(f"Found {secret_result.locator.name}: \033[92m{secret_result.secret[:100]}\033[0m in {secret_result.file_path.name} (line {secret_result.line_number})")
        results.add(secret_result)
    
    elapsed = time.time() - start
    time.sleep(3)
    pprint(f"Found {len(results)} secrets:")
    print(f"Scanning took {elapsed} seconds.")