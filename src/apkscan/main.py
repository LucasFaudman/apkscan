import argparse
from pathlib import Path
from shutil import which

from .apkscan import APKScanner

def default_rule_path(rule_filename):
    return Path(__file__).parent.parent.parent / f"secret-patterns/{rule_filename}"

DEFAULT_RULES = [
    default_rule_path("high-confidence.yml"),
]

def main():
    parser = argparse.ArgumentParser(description="Scan APK, JAR and other Java files for secrets after decompiling.")

    input_options = parser.add_argument_group("Input Options")
    input_options.add_argument(dest='files', type=Path, nargs="*", metavar="FILES_TO_SCAN",
                               help="Path to Java files to decompile and scan.")
    input_options.add_argument("-r", "--rules", type=Path, nargs="*", default=DEFAULT_RULES, metavar="SECRETS_RULES_FILES",
                               help="Path to secret locator rules/patterns files. Rule files can in Gitleak TOML, secret-patterns-db YAML, or SecretLocator JSON formats.")

    output_options = parser.add_argument_group("Output Options")
    output_options.add_argument("-o", "--output", type=Path, metavar="SECRETS_OUTPUT_FILE", default="secrets_output.json", help="Output file for secrets found.")
    output_options.add_argument("-f", "--format", type=str, choices=["text", "json", "yaml"], default="json", help="Output format for secrets found.")
    output_options.add_argument("-g", "--groupby", type=str, choices=["file", "locator", "both"], default="both", help="Group secrets by input file or locator. Default is 'both'.")

    decompiler_options = parser.add_argument_group("Decompiler Options", description="Options for Java decompiler.")
    decompiler_options.add_argument("-d", "--deobfuscate", action=argparse.BooleanOptionalAction, default=True, help="Deobfuscate file before scanning.")
    decompiler_options.add_argument("-c", "--cleanup", action=argparse.BooleanOptionalAction, default=False, help="Remove decompiled output directories after scanning.")
    decompiler_options.add_argument("-w", "--decompiler-working-dir", type=Path, default=Path.cwd(), help="Working directory where files will be decompiled.")
    decompiler_options.add_argument("-x", "--decompiler-binary", type=Path, default=Path(which("jadx") or "/usr/local/bin/jadx"), help="Path to JADX or other decompiler binary.")
    decompiler_options.add_argument("--decompiler-output-suffix", type=str, default="-decompiled", help="Suffix for decompiled output directory names. Default is '-decompiled'.")
    decompiler_options.add_argument("--decompiler-extra-args", type=str, nargs="+", help="Additional arguments to pass to JADX or other decompiler.")
    decompiler_options.add_argument("--decompiler-deobf-arg", type=str, default="--deobf", help="Argument to use to enable deobfuscation. Default is '--deobf'.")
    decompiler_options.add_argument("--decompiler-output-arg", type=str, default="--output-dir", help="Argument to use to set output directory. Default is '--output-dir'.")
    decompiler_options.add_argument("-dct", "--decompiler-concurrency-type", type=str, choices=["thread", "process", "main"], default="thread", help="Type of concurrency to use for decompilation. Default is 'thread'.")
    decompiler_options.add_argument("-dro", "--decompiler-results-order", type=str, choices=["completed", "submitted"], default="completed", help="Order to process results from decompiler. Default is 'completed'.")
    decompiler_options.add_argument("-dmw", "--decompiler-max-workers", type=int, default=6, help="Maximum number of workers to use for decompilation.")
    decompiler_options.add_argument("-dcs", "--decompiler-chunksize", type=int, default=1, help="Number of files to decompile per thread/process.")
    decompiler_options.add_argument("-dto", "--decompiler-timeout", type=int, help="Timeout for decompilation in seconds.")

    scanner_options = parser.add_argument_group("Secret Scanner Options", description="Options for secret scanner.")
    scanner_options.add_argument("-sct", "--scanner-concurrency-type", type=str, choices=["thread", "process", "main"], default="process", help="Type of concurrency to use for scanning. Default is 'process'.")
    scanner_options.add_argument("-sro", "--scanner-results-order", type=str, choices=["completed", "submitted"], default="completed", help="Order to process results from scanner. Default is 'completed'.")
    scanner_options.add_argument("-smw", "--scanner-max-workers", type=int, default=None, help="Maximum number of workers to use for scanning.")
    scanner_options.add_argument("-scs", "--scanner-chunksize", type=int, default=1, help="Number of files to scan per thread/process.")
    scanner_options.add_argument("-sto", "--scanner-timeout", type=int, help="Timeout for scanning in seconds.")

    args = parser.parse_args()

    decompiler_kwargs = {
        "deobfuscate": args.deobfuscate,
        "remove_failed_output_dirs": args.cleanup,
    }
    scanner_kwargs = {
        "secret_locator_files": args.rules,
    }

    for k, v in vars(args).items():
        if k.startswith("decompiler_"):
            decompiler_kwargs[k[11:]] = v
        elif k.startswith("scanner_"):
            scanner_kwargs[k[8:]] = v

    apk_scanner = APKScanner(
        decompiler_kwargs=decompiler_kwargs,
        scanner_kwargs=scanner_kwargs,
        output_file=args.output,
        output_format=args.format,
        groupby=args.groupby,
        cleanup=args.cleanup
    )

    try:
        apk_scanner.decompile_and_scan(args.files)
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

if __name__ == "__main__":
    main()
