from yaml import safe_load as yaml_load, YAMLError
from json import loads as json_loads, JSONDecodeError
from dataclasses import dataclass
from typing import Optional
from pathlib import Path
from re import compile as re_compile, Pattern

@dataclass
class SecretLocator:
    name: str
    pattern: str
    description: Optional[str] = None
    groups: Optional[list[str]] = None
    confidence: Optional[str] = None
    severity: Optional[str] = None

    def __hash__(self) -> int:
        return hash(self.name)

@dataclass
class SecretResult:
    secret: str
    file: Path
    line: int
    locator: SecretLocator

    def __hash__(self) -> int:
        return hash(self.secret + str(self.file) + str(self.line))


class SecretScanner:

    def __init__(self, secret_locator_files: list[Path]):
        self.secret_locators: dict[SecretLocator, Pattern] = {}
        self.results: dict[SecretLocator, list[SecretResult]] = {}
        self.load_secret_locators(secret_locator_files)

    def _load_yaml_or_json(self, file_path: Path) -> Optional[list[dict]]:
        if not file_path.exists():
            print(f"File not found: {file_path}. Skipping.")
            return None
        
        with file_path.open('f') as f:
            contents = f.read()

        try:
            return yaml_load(contents)['secrets']
        except (YAMLError, KeyError):
            try:
                return json_loads(contents)['secrets']
            except (JSONDecodeError, KeyError):
                print(f"Error loading {file_path}. Skipping.")
                return None


    def load_secret_locators(self, secret_locator_files: list[Path]) -> dict[SecretLocator, Pattern]:
        for secret_locator_file in secret_locator_files:
            if not (loaded_locators := self._load_yaml_or_json(secret_locator_file)):
                continue
            for locator in loaded_locators:
                self.secret_locators[SecretLocator(**locator)] = re_compile(locator['pattern'])
        
        return self.secret_locators
                
    
    def scan_file(self, file_path: Path) -> dict[SecretLocator, list[SecretResult]]:
        results = {}
        with file_path.open('r') as f:
            for line_number, line in enumerate(f, start=1):
                for locator, pattern in self.secret_locators.items():
                    if match := pattern.search(line):
                        secret_result = SecretResult(match.group(), file_path, line_number, locator)
                        results.setdefault(locator, []).append(secret_result)
        
        return results