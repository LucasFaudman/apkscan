# © 2023 Lucas Faudman.
# Licensed under the MIT License (see LICENSE for details).
# For commercial use, see LICENSE for additional terms.
from pathlib import Path
from typing import Optional, Generator, Iterable, Literal
from datetime import datetime
from yaml import dump as yaml_dump
from json import dump as json_dump

from .decompiler import Decompiler
from .secret_scanner import SecretScanner, SecretResult

class APKScanner:
    def __init__(self,
                 decompiler_kwargs: dict,
                 scanner_kwargs: dict,
                 output_file: Optional[Path] = None,
                 output_format: str = "json",
                 groupby: Literal["file", "locator", "both"] = "both",
                 cleanup: bool = True,
                 ):
        # workers
        self.decompiler = Decompiler(**decompiler_kwargs)
        self.secret_scanner = SecretScanner(**scanner_kwargs)
        # output
        self.output_file = output_file or Path(f"./secrets_output.{output_format}")
        self.output_format = output_format
        self.groupby = groupby
        self.cleanup = cleanup
        self.output_written = False
        self.cleaned_up = False
        # state tracking
        self.decompiling = {}
        self.decompilers_count_by_ext = {}
        self.decompile_start_time = None
        self.decompile_elapsed_time = None
        self.scanning = set()
        self.scan_start_time = None
        self.scan_elapsed_time = None
        self.last_scanned = None
        self.last_secret = None
        # counters
        self.num_files = 0
        self.num_decompiled = 0
        self.num_decompile_success = 0
        self.num_decompile_errors = 0
        self.num_scanning = 0
        self.num_scanned = 0
        self.num_secrets = 0
        self.num_unique_secrets = 0
        # results
        self.decompile_results = {}
        self.secrets_results = []
        self.unique_secrets = set()

        print(f"\nInitialized Decompiler:\n- {self.decompiler}")
        print(f"\nInitialized Secret Scanner:\n- {self.secret_scanner}")
        print(f"\nDecompiler Binaries:\n- " + "\n- ".join(map(str, self.decompiler.binary_paths.values())))
        print(f"\nSecret Locator Files:\n- " + "\n- ".join(map(str, self.secret_scanner.secret_locator_files)))
        print(f"\nOutput File:\n- {self.output_file.absolute()}\n")

    def print_status(self, end='\r'):
        if self.decompiling and not self.scanning:
            status = "Decompiling"
        elif self.decompiling and self.scanning:
            status = "Decompiling and Scanning"
        elif not self.decompiling and self.scanning:
            status = "Scanning"
        else:
            status = "COMPLETE"
        status_message = f"Status: {status} | "
        if self.num_files:
            status_message += f"Decompiled: {self.num_decompiled}/{self.num_files} ({self.num_decompiled/self.num_files*100:3f}%) | "
        if self.num_scanning:
            status_message += f"Scanned: {self.num_scanned}/{self.num_scanning} ({self.num_scanned/self.num_scanning*100:3f}%) | "
        if self.num_secrets:
            status_message += f"Secrets: {self.num_secrets} ({self.num_unique_secrets} unique) | "
        print(status_message, end=end, flush=True)

    def print_secret_found(self, secret_result: SecretResult) -> None:
        print(f"Found {secret_result.locator.name}: \033[92m{secret_result.secret[:100]}\033[0m in {secret_result.file_path}:{secret_result.line_number} (line {secret_result.line_number})\n")

    def files_to_decompile_generator(self, file_paths: Iterable[Path]) -> Generator[Path, None, None]:
        for file_path in file_paths:
            self.num_files += 1
            ext = file_path.suffix
            if not (num_decompilers := self.decompilers_count_by_ext.get(ext)):
                num_decompilers = self.decompiler.num_binaries_to_run_on_ext(ext)
                self.decompilers_count_by_ext[ext] = num_decompilers
            self.decompiling[file_path.stem] = num_decompilers

            if not self.decompile_start_time:
                self.decompile_start_time = datetime.now()
                print(f"\nDecompiling started at {self.decompile_start_time.strftime('%H:%M:%S:%SS')}\n")

            self.print_status()
            yield file_path

    def decompiled_files_generator(self, file_paths: Iterable[Path]) -> Generator[Path, None, None]:
        for file_path, output_dir, decompiled_files, success in self.decompiler.decompile_concurrently(file_paths):
            self.decompile_results[output_dir] = (file_path, decompiled_files, success)
            self.decompiling[file_path.stem] -= 1

            if success and decompiled_files:
                self.num_decompile_success += 1

                if not self.scan_start_time:
                    self.scan_start_time = datetime.now()
                    print(f"\nScanning started at {self.scan_start_time.strftime('%H:%M:%S:%SS')}\n")

                for decompiled_file in decompiled_files:
                    self.num_scanning += 1
                    self.scanning.add(decompiled_file)
                    self.print_status()
                    yield decompiled_file

            else:
                self.num_decompile_errors += 1

            if self.decompiling[file_path.stem] == 0:
                self.num_decompiled += 1
                del self.decompiling[file_path.stem]
                self.print_status('\n')

        self.decompiler.concurrent_executor.shutdown()
        if self.decompile_start_time:
            self.decompile_elapsed_time = datetime.now() - self.decompile_start_time
            print(f"\nDecompiling COMPLETE. Decompiled {self.num_decompiled} files with {self.num_decompile_errors} errors. Elapsed time: {self.decompile_elapsed_time}\n")


    def scan_secret_results_generator(self, file_paths: Generator[Path, None, None]) -> Generator[SecretResult, None, None]:
        self.scan_start_time = None
        for file_path, file_secret_results in self.secret_scanner.scan_concurrently(file_paths):
            if file_path in self.scanning:
                self.scanning.remove(file_path)
                self.num_scanned += 1

            self.last_scanned = file_path
            self.print_status()
            yield from file_secret_results

        self.print_status('\n')
        if self.scan_start_time:
            self.scan_elapsed_time = datetime.now() - self.scan_start_time
            print(f"\nScanning COMPLETE. Scanned {self.num_scanned} files with {self.num_secrets} secrets found. Elapsed time: {self.scan_elapsed_time}\n")

    def decompile_and_scan(self, file_paths: Iterable[Path]) -> list[SecretResult]:
        self.decompile_and_scan_start_time = datetime.now()
        num_secrets_before = self.num_secrets
        num_unique_secrets_before = self.num_unique_secrets

        files_to_decompile = self.files_to_decompile_generator(file_paths)
        decompiled_files = self.decompiled_files_generator(files_to_decompile)
        for secret_result in self.scan_secret_results_generator(decompiled_files):
            self.num_secrets += 1
            self.secrets_results.append(secret_result)
            if secret_result.secret not in self.unique_secrets:
                self.num_unique_secrets += 1
                self.print_secret_found(secret_result)
                self.unique_secrets.add(secret_result.secret)
            self.print_status()

        self.total_elapsed_time = datetime.now() - self.decompile_and_scan_start_time
        print(f"Found \033[92m{self.num_secrets - num_secrets_before} new secrets\033[0m ({self.num_unique_secrets - num_unique_secrets_before} unique).")
        print(f"Decompiled {self.num_decompiled} files with {self.num_decompile_errors} errors in {self.decompile_elapsed_time}.")
        print(f"Scanned {self.num_scanned} files and found {self.num_secrets} secrets in {self.scan_elapsed_time}.")
        print(f"Total Elapsed time: {datetime.now() - self.decompile_and_scan_start_time}")

        return self.secrets_results

    def make_secret_result_serializable(self, secret_result: SecretResult) -> dict:
        secret_result_dict = {
            "secret": secret_result.secret,
            "file_path": str(secret_result.file_path),
            "line_number": secret_result.line_number,
            "locator": secret_result.locator.name,
        }
        try:
            secret_result_dict["secret"] = secret_result_dict["secret"].decode()
        except Exception as e:
            print(f"Error decoding secret: {e}")
            secret_result_dict["secret"] = f'{secret_result_dict["secret"]}'
        return secret_result_dict

    def group_results_by_locator(self) -> dict[str, list[SecretResult]]:
        results_by_locator = {}
        for secret_result in self.secrets_results:
            serializable_secret_result = self.make_secret_result_serializable(secret_result)
            results_by_locator.setdefault(secret_result.locator.id, []).append(serializable_secret_result)
        return results_by_locator

    def group_results_by_input_file(self) -> dict[str, list[SecretResult]]:
        results_by_input_file = {}
        for secret_result in self.secrets_results:
            for output_dir, (file_path, decompiled_files, success) in self.decompile_results.items():
                # TODO maybe group by output_dir (decompilier) ?
                if secret_result.file_path in decompiled_files:
                    serializable_secret_result = self.make_secret_result_serializable(secret_result)
                    results_by_input_file.setdefault(str(file_path), []).append(serializable_secret_result)
                    break
        return results_by_input_file

    def write_output(self):
        print(f"\nWriting output to {self.output_file}", end="\r")
        if self.groupby == "file":
            results = self.group_results_by_input_file()
        elif self.groupby == "locator":
            results = self.group_results_by_locator()
        elif self.groupby == "both":
            results = {
                "by_file": self.group_results_by_input_file(),
                "by_locator": self.group_results_by_locator()
            }

        with self.output_file.open("w") as f:
            if self.output_format == "json":
                json_dump(results, f, indent=4)
            elif self.output_format == "yaml":
                yaml_dump(results, f, default_flow_style=False)
            else:
                f.write(str(results))

        self.output_written = True
        print(f"Output written to {self.output_file}")


    def do_cleanup(self, **cleanup_concurrency_kwargs):
        if self.cleanup and not self.cleaned_up:
            self.decompiler.cleanup(**cleanup_concurrency_kwargs)
            self.decompiler.concurrent_executor.shutdown(wait=False, cancel_pending=True)
            self.secret_scanner.concurrent_executor.shutdown(wait=False, cancel_pending=True)
        self.cleaned_up = True


    def __del__(self):
        if getattr(self, "secrets_results", False) and not getattr(self, "output_written", False):
            self.write_output()

        if getattr(self, "cleanup", False) and not getattr(self, "cleaned_up", False):
            self.do_cleanup(concurrency_type=None)
