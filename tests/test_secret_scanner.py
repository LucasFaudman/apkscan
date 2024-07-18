import pytest
from fixtures import tmp_locator_files, tmp_files_to_scan
from apkscan import SecretScanner, SecretLocator, SecretResult, load_secret_locators
from pathlib import Path


@pytest.mark.parametrize(
    "locator_file", ["secret_patterns_db.yml", "gitleaks.toml", "secret_locators.json", "simple_key_value.json"]
)
def test_load_all_formats(tmp_locator_files, locator_file):
    secret_locators = load_secret_locators([tmp_locator_files[locator_file]])
    assert isinstance(secret_locators, dict)
    assert len(secret_locators) == 3
    keys_list = list(secret_locators.keys())
    assert all(isinstance(pattern_str, str) and keys_list.count(pattern_str) == 1 for pattern_str in keys_list)
    assert all(isinstance(locator, SecretLocator) for locator in secret_locators.values())


@pytest.mark.parametrize(
    "locator_file", ["secret_patterns_db.yml", "gitleaks.toml", "secret_locators.json", "simple_key_value.json"]
)
def test_scan_files(tmp_locator_files, tmp_files_to_scan, locator_file):
    scanner = SecretScanner([tmp_locator_files[locator_file]])
    results = list(scanner.scan_concurrently(tmp_files_to_scan.values()))
    assert isinstance(results, list)
    for file_path, file_secret_results in results:
        assert isinstance(file_path, Path)
        assert isinstance(file_secret_results, list)
        assert all(isinstance(secret_result, SecretResult) for secret_result in file_secret_results)
