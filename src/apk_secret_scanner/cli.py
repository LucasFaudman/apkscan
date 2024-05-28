import argparse
from pathlib import Path
from shutil import which
from typing import Optional, Generator
from pprint import pprint

from decompiler import JavaDecompiler
from secret_scanner import SecretScanner, SecretResult


class JavaSecretScanner:
    def __init__(
        self,
        decompiler: JavaDecompiler,
        secret_scanner: SecretScanner,
        keep_decompiled_output_dirs: bool = False,
    ):
        self.decompiler = decompiler
        self.secret_scanner = secret_scanner
        self.keep_decompiled_output_dirs = keep_decompiled_output_dirs

    def decompile_and_scan(self, file_paths: list[Path]) -> Generator[SecretResult, None, None]:
        yield from self.secret_scanner.iterscan_files(file_paths=self.decompiler.iter_decompiled_files(file_paths))
        if not self.keep_decompiled_output_dirs:
            self.decompiler.remove_output_dirs()


def main():
    parser = argparse.ArgumentParser(description="Scan APK, JAR and other Java files for secrets after decompiling.")

    input_options = parser.add_argument_group("Input Options")
    input_options.add_argument(
        dest="files", type=Path, nargs="*", metavar="FILES_TO_SCAN", help="Path to Java files to decompile and scan."
    )
    input_options.add_argument(
        "-r",
        "--rules",
        type=Path,
        nargs="*",
        metavar="SECRET_RULES_FILES",
        help="Path to secret locator rules/patterns files. Rule files can in Gitleak TOML, secret-patterns-db YAML, or SecretLocator JSON formats.",
    )

    output_options = parser.add_argument_group("Output Options")
    output_options.add_argument(
        "-o", "--output", type=Path, metavar="OUTPUT_FILE", help="Output file for secrets found."
    )
    output_options.add_argument(
        "-f",
        "--format",
        type=str,
        choices=["text", "json", "yaml", "toml"],
        default="json",
        help="Output format for secrets found.",
    )

    decompiler_options = parser.add_argument_group("Decompiler Options", description="Options for Java decompiler.")
    decompiler_options.add_argument(
        "-d",
        "--deobfuscate",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Deobfuscate file before scanning.",
    )
    decompiler_options.add_argument(
        "-c",
        "--cleanup",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Remove decompiled output directories after scanning.",
    )
    decompiler_options.add_argument(
        "-w",
        "--decompiler-working-dir",
        type=Path,
        default=Path.cwd(),
        help="Working directory where files will be decompiled.",
    )
    decompiler_options.add_argument(
        "-x",
        "--decompiler-binary",
        type=Path,
        default=Path(which("jadx") or "/usr/local/bin/jadx"),
        help="Path to JADX or other decompiler binary.",
    )
    decompiler_options.add_argument(
        "--decompiler-suffix",
        type=str,
        default="-decompiled",
        help="Suffix for decompiled output directory names. Default is '-decompiled'.",
    )
    decompiler_options.add_argument(
        "--decompiler-args", type=str, nargs="+", help="Additional arguments to pass to JADX or other decompiler."
    )
    decompiler_options.add_argument(
        "--decompiler-deobf-arg",
        type=str,
        default="--deobf",
        help="Argument to use to enable deobfuscation. Default is '--deobf'.",
    )
    decompiler_options.add_argument(
        "--decompiler-output-dir-arg",
        type=str,
        default="--output-dir",
        help="Argument to use to set output directory. Default is '--output-dir'.",
    )
    decompiler_options.add_argument(
        "-dct",
        "--decompiler-concurrency-type",
        type=str,
        choices=["thread", "process", "main"],
        default="thread",
        help="Type of concurrency to use for decompilation. Default is 'thread'.",
    )
    decompiler_options.add_argument(
        "-dro",
        "--decompiler-results-order",
        type=str,
        choices=["completed", "submitted"],
        default="completed",
        help="Order to process results from decompiler. Default is 'completed'.",
    )
    decompiler_options.add_argument(
        "-dmw", "--decompiler-max-workers", type=int, help="Maximum number of workers to use for decompilation."
    )
    decompiler_options.add_argument(
        "-dcs", "--decompiler-chunksize", type=int, default=1, help="Number of files to decompile per thread/process."
    )
    decompiler_options.add_argument(
        "-dto", "--decompiler-timeout", type=int, help="Timeout for decompilation in seconds."
    )

    scanner_options = parser.add_argument_group("Secret Scanner Options", description="Options for secret scanner.")
    scanner_options.add_argument(
        "-sct",
        "--scanner-concurrency-type",
        type=str,
        choices=["thread", "process", "main"],
        default="process",
        help="Type of concurrency to use for scanning. Default is 'process'.",
    )
    scanner_options.add_argument(
        "-sro",
        "--scanner-results-order",
        type=str,
        choices=["completed", "submitted"],
        default="completed",
        help="Order to process results from scanner. Default is 'completed'.",
    )
    scanner_options.add_argument(
        "-smw", "--scanner-max-workers", type=int, help="Maximum number of workers to use for scanning."
    )
    scanner_options.add_argument(
        "-scs", "--scanner-chunksize", type=int, default=1, help="Number of files to scan per thread/process."
    )
    scanner_options.add_argument("-sto", "--scanner-timeout", type=int, help="Timeout for scanning in seconds.")

    # concurrency_options = parser.add_argument_group("Concurrency Options")
    # concurrency_options.add_argument("-dct", "--decompiler-concurrency-type", type=str, choices=["thread", "process", "main"], default="thread", help="Type of concurrency to use for decompilation. Default is 'thread'.")
    # concurrency_options.add_argument("-dro", "--decompiler-results-order", type=str, choices=["completed", "submitted"], default="completed", help="Order to process results from decompiler. Default is 'completed'.")
    # concurrency_options.add_argument("-dmw", "--decompiler-max-workers", type=int, help="Maximum number of workers to use for decompilation.")
    # concurrency_options.add_argument("-dcs", "--decompiler-chunksize", type=int, default=1, help="Number of files to decompile per thread/process.")
    # concurrency_options.add_argument("-dto", "--decompiler-timeout", type=int, help="Timeout for decompilation in seconds.")
    # concurrency_options.add_argument("-sct", "--scanner-concurrency-type", type=str, choices=["thread", "process", "main"], default="process", help="Type of concurrency to use for scanning. Default is 'process'.")
    # concurrency_options.add_argument("-sro", "--scanner-results-order", type=str, choices=["completed", "submitted"], default="completed", help="Order to process results from scanner. Default is 'completed'.")
    # concurrency_options.add_argument("-smw", "--scanner-max-workers", type=int, help="Maximum number of workers to use for scanning.")
    # concurrency_options.add_argument("-scs", "--scanner-chunksize", type=int, default=1, help="Number of files to scan per thread/process.")
    # concurrency_options.add_argument("-sto", "--scanner-timeout", type=int, help="Timeout for scanning in seconds.")

    args = parser.parse_args()

    decompiler = JavaDecompiler()
    secret_scanner = SecretScanner([Path(__file__).parent.parent.parent / "secret-patterns/high-confidence.yml"])
    apk_scanner = JavaSecretScanner(decompiler, secret_scanner)
    args.files = list(Path("/Users/lucasfaudman/Documents/SANS/SEC575/earn/apks").glob("*.apk"))[:3]
    results = []
    for secret_result in apk_scanner.decompile_and_scan(args.files):
        print(
            f"\n\033[92mFound {secret_result.locator.name}: {secret_result.secret[:100]} \033[0min {secret_result.file_path.name} (line {secret_result.line_number})"
        )
        results.append(secret_result)

    pprint(results)


if __name__ == "__main__":
    main()
