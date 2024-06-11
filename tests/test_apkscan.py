import pytest
from fixtures import tmp_locator_files, tmp_files_to_scan
from apkscan import APKScanner, SecretLocator, SecretResult, load_secret_locators
from pathlib import Path

if __name__ == "__main__":
    tmpdir = Path("./testoutput")
    decompiler_kwargs = {
        "binaries": [
            "jadx",
            # "procyon",
            # "cfr",
            # "apktool",
            ],
        "working_dir": tmpdir,
        "overwrite": False,
        "suppress_output": False,
    }
    scanner_kwargs = {
        "secret_locator_files": [Path('/Users/lucasfaudman/Documents/SANS/SEC575/disa/apkscan/secret-patterns/default.json')],
    }

    test_output = Path("test_output.json")
    test_apks =  [Path(__file__).parent / "test_apks" / test_apk
                  for test_apk in [
                    "test-apk-1.apk",
                    # "test-xapk-1.xapk",
                  ]
    ]
    apk_scanner = APKScanner(decompiler_kwargs, scanner_kwargs, output_file=test_output, cleanup=False)

    try:
        apk_scanner.decompile_and_scan(test_apks)
    except KeyboardInterrupt:
        print("\nWriting output, cleaning up, and exiting...")
    finally:
        apk_scanner.write_output()
        apk_scanner.do_cleanup()

    if apk_scanner.secrets_results:
        print(f"\nAPKscan done. Secrets saved to {apk_scanner.output_file}")
        exit(0)
    else:
        print("\nAPKscan done. No secrets found.")
        exit(1)
