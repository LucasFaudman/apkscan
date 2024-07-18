# © 2024 Lucas Faudman.
# Licensed under the MIT License (see LICENSE for details).
# For commercial use, see LICENSE for additional terms.
import pytest
from pathlib import Path


@pytest.fixture
def tmp_locator_files(tmpdir) -> dict[str, Path]:
    secret_patterns_db_yaml = r"""patterns:
  - pattern:
      name: AWS Access Token
      regex: (A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}
      confidence: high
  - pattern:
      name: GCP API Key
      regex: (?i)\b(AIza[0-9A-Za-z\\-_]{35})(?:['|\"|\n|\r|\s|\x60|;]|$)
      confidence: high
  - pattern:
      name:  Generic API Key
      regex: '[aA][pP][iI]_?[kK][eE][yY].*[''|"][0-9a-zA-Z]{32,45}[''|"]'
      confidence: high
"""

    gitleaks_toml = r"""
title = "gitleaks config"

[[rules]]
description = "AWS"
id = "aws-access-token"
regex = '''(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'''
keywords = [
    "akia","agpa","aida","aroa","aipa","anpa","anva","asia",
]

[[rules]]
description = "GCP API key"
id = "gcp-api-key"
regex = '''(?i)\b(AIza[0-9A-Za-z\\-_]{35})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "aiza",
]

[[rules]]
description = "Generic API Key"
id = "generic-api-key"
regex = '''[aA][pP][iI]_?[kK][eE][yY].*[''|"][0-9a-zA-Z]{32,45}[''|"]'''
secretGroup = 1
entropy = 3.5
keywords = [
    "key","api","token","secret","client","passwd","password","auth","access",
]
[rules.allowlist]
stopwords= [
    "client",
    "endpoint",
    "vpn",
]


"""

    secret_locators_json = r"""
[
    {
        "id": "aws-access-token",
        "name": "AWS Access Key ID Value",
        "pattern": "(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "confidence": "high"
    },
    {
        "id": "gcp-api-key",
        "name": "GCP API Key",
        "pattern": "(?i)\\b(AIza[0-9A-Za-z\\-_]{35})(?:['|\"|\\n|\\r|\\s|\\x60|;]|$)",
        "confidence": "high"
    },
    {
        "id": "generic-api-key",
        "name": "Generic API Key",
        "pattern": "(?i)(?:key|api|token|secret|client|passwd|password|auth|access)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\"|\\s|=|\\x60){0,5}([0-9a-z\\-_\\.=]{10,150})(?:['|\"|\\n|\\r|\\s|\\x60|;]|$)",
        "confidence": "high"
    }
]
"""

    simple_key_value_json = r"""
{
    "AWS Access Key ID Value": "(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "GCP API Key": "(?i)\\b(AIza[0-9A-Za-z\\-_]{35})(?:['|\"|\\n|\\r|\\s|\\x60|;]|$)",
    "Generic API Key": "(?i)(?:key|api|token|secret|client|passwd|password|auth|access)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\"|\\s|=|\\x60){0,5}([0-9a-z\\-_\\.=]{10,150})(?:['|\"|\\n|\\r|\\s|\\x60|;]|$)"
}
"""
    tmpdir_path = Path(tmpdir)
    temp_file_names = {
        "secret_patterns_db.yml": secret_patterns_db_yaml,
        "gitleaks.toml": gitleaks_toml,
        "secret_locators.json": secret_locators_json,
        "simple_key_value.json": simple_key_value_json,
    }
    temp_paths = {}
    for file_name, content in temp_file_names.items():
        temp_path = tmpdir_path / file_name
        temp_path.write_text(content)
        temp_paths[file_name] = temp_path
    # temp_paths["tmpdir_path"] = tmpdir_path
    return temp_paths


@pytest.fixture
def tmp_files_to_scan(tmpdir):
    aws_key_file = """Line 1
Line 2 ASIAY34FZKBOKMUTVV7A
"""
    gcp_key_file = """Line 1
Line 2 AIzaSyDRKQ9d6kfsoZT2lUnZcZnBYvH69HExNPE
"""
    generic_key_file = """Line 1
Line 2 secret=1234567890
"""

    nested_mix_file = """Line 1
Line 2 ASIAY34FZKBOKMUTVV7A
Line 3 AIzaSyDRKQ9d6kfsoZT2lUnZcZnBYvH69HExNPE
Line 4 API_KEY=1234567890
"""
    tmpdir_path = Path(tmpdir)
    nested_dir = tmpdir_path / "nested_dir"
    nested_dir.mkdir()
    temp_file_names = {
        "aws_key_file.java": aws_key_file,
        "gcp_key_file.java": gcp_key_file,
        "generic_key_file.java": generic_key_file,
        "nested_mix_file.java": nested_mix_file,
    }
    temp_paths = {}
    for file_name, content in temp_file_names.items():
        temp_path = tmpdir_path / file_name
        temp_path.write_text(content)
        temp_paths[file_name] = temp_path

    return temp_paths
