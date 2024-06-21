# APKscan
![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)
![Java](https://img.shields.io/badge/java-%23ED8B00.svg?style=for-the-badge&logo=openjdk&logoColor=white)
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Scan for **secrets**, **endpoints**, and other **sensitive data** after **decompiling** and **deobfuscating** Android
files. (.apk, .xapk, .dex, .jar, .class, .smali, .zip, .aar, .arsc, .aab, .jadx.kts).

- [Why use APKscan?](#why-use-apkscan)
- [Features](#features)
- [Installation](#installation)
  - [PyPi Install Command](#pypi-install-command)
  - [From Source Install Commands](#from-source-install-commands)
- [Usage](#usage)
    - [Basic Usage](#basic-usage)
    - [Advanced Usage (All Command Line Arguments)](#advanced-usage)
- [Configuring Scanning Rules](#configuring-scanning-rules-secret-locators)
    - [Secret Locator Structure](#secret-locator-structure)
    - [Supported Secret Locator Input Formats](#supported-secret-locator-input-formats)
    - [Secret Locator Input Examples](#secretlocator-json-or-yaml-format)
- [Configuring Decompilers](#configuring-decompilers)
    - [Supported Decompilers](#supported-decompilers)
    - [Using Multiple Decompilers](#using-multiple-decompilers)
    - [Why use Multiple Decompilers?](#variety-of-decompilation-techniques)
- [Concurrency and Performance](#concurrency-and-performance)
    - [Concurrency Options](#concurrency-options)
        - [Concurrency Type](#concurrency-type)
        - [Results Order](#results-order)
        - [Max Workers](#max-workers)
        - [Chunksize](#chunk-size-multiprocessing-and-order-submitted-only)
        - [Timeout](#timeout)
    - [Optimizing Performance](#optimizing-performance)
- [Contributing](#contributing)
- [License](#license)

---

## Why use APKscan?

### Find Leaked Secrets
APKs (Android Package Kits) often leak secrets due to over-reliance on *security through obscurity*. Developers sometimes leave **sensitive information** such as **API keys**, **tokens**, and **credentials** hidden within the code, assuming that they won't be found easily since the code has been compiled and obfuscated. However, this approach is fundamentally flawed, and such secrets can be exposed, leading to potential **security vulnerabilities**.

### Identify Sensitive Locations in Application Code
APKscan can help quickly identify sensitive locations in the code, such as SSL pinning libraries, root detection functions, and other security mechanisms. Identifying these functions can speed up reverse engineering and app manipulation by **quickly revealing critical points where an app enforces its security policies, making it easier to bypass them with tools like Frida.** By pinpointing these areas, APKscan aids in understanding an app's security mechanisms and potential weaknesses.

### Identify the Attack Surface of the Backend
APKscan also helps identify the attack surface of the backend by uncovering **forgotten endpoints**, **test data payloads**, and other **traces of backend interfaces** that developers might have **unintentionally exposed**. These endpoints can provide attackers with access to sensitive data or functionalities that are not meant for public use. By scanning for such endpoints and test data, APKscan assists in ensuring that the backend is secure and that **no unnecessary exposure is left in the deployed applications**.


## Features

### Automate the Scanning Process for Multiple Applications:
> APKscan allows you to automate the process of scanning for secrets in **any number of applications**, saving you time and ensuring thorough coverage.

### Multiple Decompilers and Deobfuscators:
> Utilize one or more decompilers and deobfuscators to increase the chances of finding hidden secrets.
- Supports all popular decompilers including `JADX`, `APKTool`, `CFR`, `Procyon`, `Krakatau`, and `Fernflower`, providing flexibility and robustness in your scanning process.
- Uses [`enjarify-adapter`](https://github.com/LucasFaudman/enjarify-adapter) to convert the Dalvik bytecode in `.apk` files into Java bytecode on the fly, so the resulting `.jar` can be processed by decompilers/deobfuscators that do not support `.apks` directly.

### Customizable Rules:
> Define your own secret locator rules or use the default ones provided. This flexibility allows you to tailor the scanning process to your specific needs and improve the detection accuracy of sensitive information.
- Support for common formats: `SecretLocator JSON`, `secret-patterns-db YAML`, `gitleaks TOML`, and simple key-value pairs.

### Flexible Output Options:
> Choose from multiple output formats (`JSON`, `YAML`, or `text`) and organize the results by input file or locator. This makes it easier to integrate with other tools and workflows, and to analyze the findings effectively.

### Comprehensive File Support:
> Decompile and scan a wide range of Android-related files, including `.apk,` `.xapk,` `.dex,` `.jar,` `.class,` `.smali,` `.zip,` `.aar,` `.arsc,` `.aab,` and `.jadx.kts` files.

### Advanced Configuration and Concurrency Options:
> APKscan offers advanced options for concurrency, decompilation, and scanning, enabling you to optimize the performance and behavior of the tool to suit your environment and requirements.

---

## Installation
> APKscan can be installed from PyPi or from source.

### PyPi Install Command
```bash
pip3 install apkscan
```

### From Source Install Commands
```bash
git clone https://github.com/LucasFaudman/apkscan.git
cd apkscan
python3 -m venv .venv
source .venv/bin/activate
pip3 install -e .
```

---


## Usage

### Basic Usage
The most basic way to use APKscan is to decompile an APK using the default decompiler `JADX` and scan using the default Secret locator rules in [`default.json`](https://github.com/LucasFaudman/apkscan/blob/main/src/apkscan/secret_locators/default.json).
```bash
apkscan apk-file-to-scan.apk
```
---
A slighly more complex example. This time 3 APKs will be decompiled then scanned using the custom rules at `/path/to/custom/rules.json`. The output written to `output_file.yaml` in `YAML` format, and the results will be grouped by which secret locator was matched. Files generated during decompilation will be removed after scanning.
```bash
apkscan -r /path/to/custom/rules.json -o output_file.yaml -f yaml -g locator -c
```
Or in long form:
```bash
apkscan --rules /path/to/custom/rules.json --output output_file.yaml --format yaml --groupby locator --cleanup
```
---


### Advanced Usage

<details>
<summary>
<h4>All Command Line Arguments</h4>
</summary>

```bash
usage: apkscan [-h] [-r [SECRET_LOCATOR_FILES ...]] [-o SECRETS_OUTPUT_FILE]
               [-f {text,json,yaml}] [-g {file,locator,both}]
               [-c | --cleanup | --no-cleanup] [-q] [--jadx [JADX]]
               [--apktool [APKTOOL]] [--cfr [CFR]] [--procyon [PROCYON]]
               [--krakatau [KRAKATAU]] [--fernflower [FERNFLOWER]]
               [--enjarify-choice {auto,never,always}]
               [-d | --deobfuscate | --no-deobfuscate]
               [-w DECOMPILER_WORKING_DIR]
               [--decompiler-output-suffix DECOMPILER_OUTPUT_SUFFIX]
               [--decompiler-extra-args DECOMPILER_EXTRA_ARGS [DECOMPILER_EXTRA_ARGS ...]]
               [-dct {thread,process,main}] [-dro {completed,submitted}]
               [-dmw DECOMPILER_MAX_WORKERS] [-dcs DECOMPILER_CHUNKSIZE]
               [-dto DECOMPILER_TIMEOUT] [-sct {thread,process,main}]
               [-sro {completed,submitted}] [-smw SCANNER_MAX_WORKERS]
               [-scs SCANNER_CHUNKSIZE] [-sto SCANNER_TIMEOUT]
               [FILES_TO_SCAN ...]

APKscan v0.2.2 - Scan for secrets, endpoints, and other sensitive data after decompiling and deobfuscating Android files. (.apk, .xapk, .dex, .jar, .class, .smali, .zip, .aar, .arsc, .aab, .jadx.kts) (c) Lucas Faudman, 2024. License information in LICENSE file. Credits to the original authors of all dependencies used in this project.

options:
  -h, --help            show this help message and exit

Input Options:
  FILES_TO_SCAN         Path to Java files to decompile and scan.
  -r [SECRET_LOCATOR_FILES ...], --rules [SECRET_LOCATOR_FILES ...]
                        Path to secret locator rules/patterns files. Files can
                        in SecretLocator JSON, secret-patterns-db YAML, or
                        Gitleak TOML formats. If not provided, default rules
                        will be used. See: /Users/lucasfaudman/Documents/SANS/
                        SEC575/disa/apkscan/src/apkscan/secret_locators/defaul
                        t.json

Output Options:
  -o SECRETS_OUTPUT_FILE, --output SECRETS_OUTPUT_FILE
                        Output file for secrets found.
  -f {text,json,yaml}, --format {text,json,yaml}
                        Output format for secrets found.
  -g {file,locator,both}, --groupby {file,locator,both}
                        Group secrets by input file or locator. Default is
                        'both'.
  -c, --cleanup, --no-cleanup
                        Remove decompiled output directories after scanning.
  -q, --quiet           Suppress output from subprocesses.

Decompiler Choices:
  Choose which decompiler(s) to use. Optionally specify path to decompiler
  binary. Default is JADX.

  --jadx [JADX], -J [JADX]
                        Use JADX Java decompiler.
  --apktool [APKTOOL], -A [APKTOOL]
                        Use APKTool SMALI disassembler.
  --cfr [CFR], -C [CFR]
                        Use CFR Java decompiler. Requires Enjarify.
  --procyon [PROCYON], -P [PROCYON]
                        Use Procyon Java decompiler. Requires Enjarify.
  --krakatau [KRAKATAU], -K [KRAKATAU]
                        Use Krakatau Java decompiler. Requires Enjarify.
  --fernflower [FERNFLOWER], -F [FERNFLOWER]
                        Use Fernflower Java decompiler. Requires Enjarify.
  --enjarify-choice {auto,never,always}, -EC {auto,never,always}
                        When to use Enjarify. Default is 'auto' which means
                        use only when needed.

Decompiler Advanced Options:
  Options for Java decompiler.

  -d, --deobfuscate, --no-deobfuscate
                        Deobfuscate file before scanning.
  -w DECOMPILER_WORKING_DIR, --decompiler-working-dir DECOMPILER_WORKING_DIR
                        Working directory where files will be decompiled.
  --decompiler-output-suffix DECOMPILER_OUTPUT_SUFFIX
                        Suffix for decompiled output directory names. Default
                        is '-decompiled'.
  --decompiler-extra-args DECOMPILER_EXTRA_ARGS [DECOMPILER_EXTRA_ARGS ...]
                        Additional arguments to pass to decompilers in form
                        quoted whitespace separated '<DECOMPILER_NAME>
                        <EXTRA_ARGS>...'. For example: --decompiler-extra-args
                        'jadx --no-debug-info,--no-inline'.
  -dct {thread,process,main}, --decompiler-concurrency-type {thread,process,main}
                        Type of concurrency to use for decompilation. Default
                        is 'thread'.
  -dro {completed,submitted}, --decompiler-results-order {completed,submitted}
                        Order to process results from decompiler. Default is
                        'completed'.
  -dmw DECOMPILER_MAX_WORKERS, --decompiler-max-workers DECOMPILER_MAX_WORKERS
                        Maximum number of workers to use for decompilation.
  -dcs DECOMPILER_CHUNKSIZE, --decompiler-chunksize DECOMPILER_CHUNKSIZE
                        Number of files to decompile per thread/process.
  -dto DECOMPILER_TIMEOUT, --decompiler-timeout DECOMPILER_TIMEOUT
                        Timeout for decompilation in seconds.

Secret Scanner Advanced Options:
  Options for secret scanner.

  -sct {thread,process,main}, --scanner-concurrency-type {thread,process,main}
                        Type of concurrency to use for scanning. Default is
                        'process'.
  -sro {completed,submitted}, --scanner-results-order {completed,submitted}
                        Order to process results from scanner. Default is
                        'completed'.
  -smw SCANNER_MAX_WORKERS, --scanner-max-workers SCANNER_MAX_WORKERS
                        Maximum number of workers to use for scanning.
  -scs SCANNER_CHUNKSIZE, --scanner-chunksize SCANNER_CHUNKSIZE
                        Number of files to scan per thread/process.
  -sto SCANNER_TIMEOUT, --scanner-timeout SCANNER_TIMEOUT
                        Timeout for scanning in seconds.

```
</details>

---


## Configuring Scanning Rules: (Secret Locators)
A Secret Locator is a specific pattern designed to detect sensitive information within files. These locators help automate the identification of secrets, such as API keys, client IDs, passwords, and other sensitive data that may inadvertently be included in codebases. Here’s a breakdown of how a Secret Locator is structured and how to configure them for your scans:

### Secret Locator Structure
> Example Secret Locator for OpenAI API key in JSON:
```json
    {
        "id": "openai-api-key",
        "name": "OpenAI API Key",
        "pattern": "sk-\\w{20}T3BlbkFJ\\w{20}",
        "secret_group": 0,
        "description": "OpenAI API Key",
        "confidence": "high",
        "severity": "high",
        "tags": [
            "OpenAI",
            "API Key",
            "Secret Key",
            "AI"
        ]
    },
```

| Field | Required | Description | Used For |
| --- | --- | --- | --- |
| `id` | Yes | Unique identifier for the locator. | Grouping output by locator. |
| `name` | Yes | Display name for the locator. | Printed when found, upcoming features. |
| `pattern` | Yes | Unique Regex Pattern to search for. | Regex to match when locating secrets. |
| `secret_group` | No | Regex capturing group number to extract. Defaults to 0 (entire match) | Extracting the secret from a match. |
| `description` | No | Description of the secret and it's impact if leaked. | Upcoming features (search). |
| `confidence` | No | How likely a match is to be a true positive. | Upcoming features (search, filter output) |
| `severity` | No | How severe the risk of leaking this secret is. | Upcoming features (search, filter output) |
| `tags` | No | Tags/keywords | Upcoming features (search, filter output) |

### Supported Secret Locator Input Formats
APKscan supports multiple common formats for secret patterns including:
| Format | Filetype(s) | Link to More Patterns | Credit |
| --- | --- | --- | --- |
| `SecretLocator` | `JSON`, `YAML` | [all_secret_locators.json](https://github.com/LucasFaudman/apkscan/blob/main/src/apkscan/secret_locators/all_secret_locators.json) | @lucasfaudman
| `secret-patterns-db` | `YAML` | [Link to DB](https://github.com/mazen160/secrets-patterns-db/tree/master/db) | @zricethezav
| `gitleaks` | `TOML` | [Link to Gitleaks](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml)| @mazen160 |
| Key-value pairs. | `JSON`, `YAML` | [Link](https://www.google.com/search?q=regexes+for+secrets) | @douglascrockford |

> NOTE: Multiple files in different formats can be provided at once after the `-r/--rules` arg. Duplicate patterns will be removed. Duplicate IDs will be combined in the output.

**Need another format?** Feel free to open an Issue, edit [`def load_secret_locators` in `secret_scanner.py`](https://github.com/LucasFaudman/apkscan/blob/02e47c105f3d0b32d2bd15c94c1bc5df8dcc8ccb/src/apkscan/secret_scanner.py#L144), and/or open a PR.


<details>
<summary>
<h3>Secret Locator Format Examples</h3>
</summary>

#### `SecretLocator` `JSON` or `YAML` format.
```json
[
    {
        "id": "gcp-api-key",
        "name": "GCP API Key",
        "pattern": "\\b(AIza[0-9A-Za-z\\\\-_]{35})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)",
        "secret_group": 1,
        "description": "Google Cloud Platform API key",
        "confidence": "high",
        "severity": null,
        "tags": [
            "Google",
            "Cloud",
            "API Key"
        ]
    },
    {
        "id": "generic-key",
        "name": "Generic Key",
        "pattern": "(?i)\\b\\w+(?:secret_?)?(?:api_?)?key[\\s=:]+[\\'\"][\\w/\\-:@.]+[\\'\"]",
        "secret_group": 0,
        "description": null,
        "confidence": "low",
        "severity": null,
        "tags": []
    }
]
```

#### `secret-patterns-db YAML` format.
```yaml
patterns:
  - pattern:
      name: AWS API Gateway
      regex: "[0-9a-z]+.execute-api.[0-9a-z.-_]+.amazonaws.com"
      confidence: low
  - pattern:
      name: AWS ARN
      regex: "arn:aws:[a-z0-9-]+:[a-z]{2}-[a-z]+-[0-9]+:[0-9]+:.+"
      confidence: low
  - pattern:
      name: AWS Client ID
      regex: "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
      confidence: low
```

#### `gitleaks TOML`
```toml
title = "gitleaks config"
[[rules]]
description = "Alibaba AccessKey ID"
id = "alibaba-access-key-id"
regex = '''(?i)\b((LTAI)(?i)[a-z0-9]{20})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
keywords = [
    "ltai",
]

[[rules]]
description = "Alibaba Secret Key"
id = "alibaba-secret-key"
regex = '''(?i)(?:alibaba)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{30})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "alibaba",
]

[[rules]]
description = "Asana Client ID"
id = "asana-client-id"
regex = '''(?i)(?:asana)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9]{16})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "asana",
]
```

#### Key-value pairs.
```json
{
    "OpenAI API Key": "sk-\\w{20}T3BlbkFJ\\w{20}",
    "GCP API Key": "\\b(AIza[0-9A-Za-z\\\\-_]{35})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)",
    "Generic Key": "(?i)\\b\\w+(?:secret_?)?(?:api_?)?key[\\s=:]+[\\'\"][\\w/\\-:@.]+[\\'\"]"
}
```

</details>

---


## Configuring Decompilers
APKscan supports many popular APK and Java decompiler/disassemblers/deobfuscators increasing the chance of successfully finding secrets.

> NOTE: APKscan uses [`enjarify-adapter`](https://github.com/LucasFaudman/enjarify-adapter) to convert the Dalvik bytecode in `.apk` files into Java bytecode on the fly, so the resulting `.jar` can be processed by decompilers/deobfuscators that do not support `.apks` directly.


### Supported Decompilers

| Tool | Requires Enjarify | Link to Project | Credit |
| --- | --- | --- | --- |
`JADX` | No | [Link](https://github.com/skylot/jadx) | @skylot |
`APKTool` | No | [Link](https://github.com/iBotPeaches/Apktool) | @iBotPeaches |
`CFR` | Yes | [Link](https://github.com/leibnitz27/cfr) | @leibnitz27 |
`Procyon` | Yes | [Link](https://github.com/mstrobel/procyon) | @mstrobel |
`Krakatau` | Yes | [Link](https://github.com/Storyyeller/Krakatau) | @Storyyeller |
`Fernflower` | Yes | [Link](https://github.com/fesh0r/fernflower) | @fernflower |

### Using Multiple Decompilers
Multiple decompilers can be used at once by providing the arguments below. Each optionally accepts a path to the binary of the tool. When no path is provided the binary on the standard path is used. (output of `which jadx`, `which apktool`, etc)

```bash
Decompiler Choices:
  Choose which decompiler(s) to use. Optionally specify path to decompiler
  binary. Default is JADX.

  --jadx [JADX], -J [JADX]
                        Use JADX Java decompiler.
  --apktool [APKTOOL], -A [APKTOOL]
                        Use APKTool SMALI disassembler.
  --cfr [CFR], -C [CFR]
                        Use CFR Java decompiler. Requires Enjarify.
  --procyon [PROCYON], -P [PROCYON]
                        Use Procyon Java decompiler. Requires Enjarify.
  --krakatau [KRAKATAU], -K [KRAKATAU]
                        Use Krakatau Java decompiler. Requires Enjarify.
  --fernflower [FERNFLOWER], -F [FERNFLOWER]
                        Use Fernflower Java decompiler. Requires Enjarify.
  --enjarify-choice {auto,never,always}, -EC {auto,never,always}
                        When to use Enjarify. Default is 'auto' which means
                        use only when needed.

Decompiler Advanced Options:
  Options for Java decompiler.

  -d, --deobfuscate, --no-deobfuscate
                        Deobfuscate file before scanning.
  -w DECOMPILER_WORKING_DIR, --decompiler-working-dir DECOMPILER_WORKING_DIR
                        Working directory where files will be decompiled.
  --decompiler-output-suffix DECOMPILER_OUTPUT_SUFFIX
                        Suffix for decompiled output directory names. Default is '-decompiled'.
  --decompiler-extra-args DECOMPILER_EXTRA_ARGS [DECOMPILER_EXTRA_ARGS ...]
                        Additional arguments to pass to decompilers in form quoted whitespace separated '<DECOMPILER_NAME>
                        <EXTRA_ARGS>...'. For example: --decompiler-extra-args 'jadx --no-debug-info,--no-inline'.
```

**Examples:**

Decompile with both `JADX` and `APKtool`:
```bash
apkscan --jadx --apktool -o "combined-output.json" app-to-scan.apk
```
Decompile with `JADX` located at `"/non/standard/path/jadx"`, `Procyon` and `CFR` binaries in the standard location:
```bash
apkscan --jadx "/non/standard/path/jadx" --cfr --procyon -o "combined-output.json" app-to-scan.apk
```
Decompile multiple APKs with all decompilers and output `YAML`:
```bash
apkscan -JACPKF -o "combined.yaml' -f yaml app-to-scan1.apk app-to-scan2.apk app-to-scan3.xapk
```
Provide extra args to `JADX` and `CFR`:
```bash
apkscan --jadx --cfr --decompiler-extra-args "jadx  --add-debug-lines --no-inline-anonymous" "cfr --renamedupmembers true" app-to-scan.apk
```

<details>
<summary>
<h3>Why use Multiple Decompilers?</h3>
</summary>

Using multiple decompilers increases the chance of successfully finding secrets for several reasons:

#### Variety of Decompilation Techniques:
Different decompilers use various algorithms and heuristics to reverse-engineer bytecode back into source code. By leveraging multiple decompilers, you can capture a broader spectrum of decompilation strategies, increasing the likelihood of accurately reconstructing the original source code.

#### Handling Obfuscation:
APKs often use obfuscation techniques to make reverse engineering more difficult. Some decompilers are better at handling specific types of obfuscation than others. By using multiple decompilers, you can overcome a wider range of obfuscation techniques, ensuring more thorough analysis.

#### Completeness of Decompiled Output:
No single decompiler can guarantee perfect output for all APKs. Some decompilers might miss certain parts of the code or fail to decompile specific constructs correctly. Combining the outputs from multiple decompilers helps ensure a more complete and accurate reconstruction of the application.

#### Redundancy and Validation:
Having multiple decompiled versions of the same APK allows for cross-verification. Discrepancies between the outputs can be analyzed to identify potential decompilation errors or areas that need further investigation.

</details>

---

## Concurrency and Performance
APKscan offers a comprehensive set of concurrency and performance options that are configurable in a similar way for both decompilation and secret scanning processes. These options allow you to optimize the speed and efficiency of APKscan based on your system's capabilities and the size of your workload.

### Concurrency Options
Both the decompilation **AND** secret scanning processes can be configured using the following options:

```bash
Decompiler Advanced Options:
  Options for Java decompiler.
    <truncated>
  -dct {thread,process,main}, --decompiler-concurrency-type {thread,process,main}
                        Type of concurrency to use for decompilation. Default is 'thread'.
  -dro {completed,submitted}, --decompiler-results-order {completed,submitted}
                        Order to process results from decompiler. Default is 'completed'.
  -dmw DECOMPILER_MAX_WORKERS, --decompiler-max-workers DECOMPILER_MAX_WORKERS
                        Maximum number of workers to use for decompilation.
  -dcs DECOMPILER_CHUNKSIZE, --decompiler-chunksize DECOMPILER_CHUNKSIZE
                        Number of files to decompile per thread/process.
  -dto DECOMPILER_TIMEOUT, --decompiler-timeout DECOMPILER_TIMEOUT
                        Timeout for decompilation in seconds.

Secret Scanner Advanced Options:
  Options for secret scanner.

  -sct {thread,process,main}, --scanner-concurrency-type {thread,process,main}
                        Type of concurrency to use for scanning. Default is 'process'.
  -sro {completed,submitted}, --scanner-results-order {completed,submitted}
                        Order to process results from scanner. Default is 'completed'.
  -smw SCANNER_MAX_WORKERS, --scanner-max-workers SCANNER_MAX_WORKERS
                        Maximum number of workers to use for scanning.
  -scs SCANNER_CHUNKSIZE, --scanner-chunksize SCANNER_CHUNKSIZE
                        Number of files to scan per thread/process.
  -sto SCANNER_TIMEOUT, --scanner-timeout SCANNER_TIMEOUT
                        Timeout for scanning in seconds.

```

#### Concurrency Type:
> Specify the type of concurrency to use with `{thread, process, main}`.
- `thread`: Uses threading, suitable for I/O-bound tasks.
- `process`: Uses multiprocessing, more efficient for CPU-bound tasks.
- `main`: Runs in the main thread, useful for debugging or environments where concurrency is restricted.

#### Results Order:
> Control the order in which results are processed with `{completed, submitted}`.
- `completed`: Processes results as soon as they are completed.
- `submitted`: Processes results in the order they were submitted.

#### Max Workers:
> Set the maximum number of workers (threads or processes) to use.
- Adjust based on your system's CPU and memory resources.

#### Chunk Size (Multiprocessing and order submitted ONLY):
> Define the number of files to submit for processing process.
- This helps balance the workload and can improve performance.

#### Timeout:
> Set a timeout for each thread/process in seconds.
- This ensures that stalled tasks do not indefinitely block the overall process.


### Optimizing Performance
To optimize the performance of APKscan, consider the following tips:

1. Decompilation is memory-intensive: Set the maximum number of decompiler workers based on your available RAM to avoid system slowdowns or crashes.
2. Balance workload between decompilation and scanning: Consider whether your workload is more focused on decompiling or scanning.
    - If using a large number of decompilers and scanning for few secret locators, allocate more workers to decompilation and fewer to scanning.
    - Conversely, if using fewer decompilers but scanning for many secret locators, allocate more workers to the scanning process.

By fine-tuning these concurrency and performance options, you can make the most of APKscan's capabilities, ensuring efficient and effective secret detection across large and diverse sets of files.


---

## Contributing

Contributions welcome! Whether you're interested in fixing bugs, adding new features, improving documentation, or sharing ideas, any input is valuable.

### How to Contribute

1. **Fork the Repository**: Start by forking the repository on GitHub. This will create a copy of the project in your own GitHub account.

2. **Clone the Repository**: Clone the forked repository to your local machine.

    ```bash
    git clone https://github.com/LucasFaudman/apkscan.git
    cd apkscan
    ```

3. **Create a Branch**: Create a new branch for your changes.

    ```bash
    git checkout -b my-feature-branch
    ```

4. **Make Changes**: Make your changes in the code, documentation, or both.

5. **Commit Changes**: Commit your changes with a descriptive commit message.

    ```bash
    git add .
    git commit -m "Description of the changes"
    ```

6. **Push Changes**: Push your changes to your forked repository.

    ```bash
    git push origin my-feature-branch
    ```

7. **Create a Pull Request**: Go to the original repository and create a pull request from your branch. Provide a detailed description of your changes and any relevant information.

### Issues

If you encounter any bugs, have suggestions, or need help, please open an issue on GitHub. Make sure to provide as much detail as possible, including steps to reproduce the issue, error messages, and screenshots if applicable.


---


## License
> See [LICENSE](https://github.com/LucasFaudman/apkscan/blob/main/LICENSE) for details.
