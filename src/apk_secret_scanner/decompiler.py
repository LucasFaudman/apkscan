from subprocess import run, CompletedProcess, SubprocessError
from pathlib import Path
from shutil import which, rmtree
from typing import Optional, Iterator, Literal

from concurrent_executor import ConcurrentExecutor


class JavaDecompiler:
    def __init__(
        self,
        decompiler_binary: Path = Path(which("jadx") or "/usr/local/bin/jadx"),
        decompiler_args: Optional[list[str]] = None,
        deobfuscate: bool = False,
        deobfuscation_arg: str = "--deobf",
        output_dir_arg: str = "--output-dir",
        output_dir_suffix: str = "-decompiled",
        working_directory: Path = Path(
            "/Users/lucasfaudman/Documents/SANS/SEC575/testoutput"
        ),  # Path("/tmp/apk-secret-scanner")
        remove_failed_output_dirs: bool = True,
        **concurrent_executor_kwargs,
    ):
        self.decompiler_binary = decompiler_binary
        self.decompiler_args = decompiler_args if decompiler_args is not None else []
        self.deobfuscate = deobfuscate
        self.deobfuscation_arg = deobfuscation_arg
        self.output_dir_arg = output_dir_arg
        self.output_dir_suffix = output_dir_suffix
        self.working_directory = working_directory
        self.remove_failed_output_dirs = remove_failed_output_dirs
        self.output_dirs = {}
        self.concurrent_executor = ConcurrentExecutor(**{"concurrency_type": "thread", **concurrent_executor_kwargs})

    def decompile(self, file_path: Path) -> tuple[Path, Path, bool]:
        file_name = file_path.name
        output_dir = self.working_directory / (file_name + self.output_dir_suffix)
        self.output_dirs[file_path] = output_dir
        if not output_dir.exists():
            print(f"Creating output directory: {output_dir}")
            output_dir.mkdir(parents=True, exist_ok=True)
            print(f"Output directory created: {output_dir}")

        decompiler_args = [self.decompiler_binary, file_path, self.output_dir_arg, output_dir]
        if self.decompiler_args:
            decompiler_args.extend(self.decompiler_args)
        if self.deobfuscate:
            decompiler_args.append(self.deobfuscation_arg)

        try:
            print(f"Running {self.decompiler_binary.name} decompiler on {file_name}")
            result = run(list(map(str, decompiler_args)))
            success = result.returncode == 0
            print(f"Decompilation of {file_name} completed successfully.")
        except SubprocessError as e:
            success = False
            print(f"Error decompiling {file_name}: {e}")
            if self.remove_failed_output_dirs:
                self.remove_output_dir(output_dir)

        return file_path, output_dir, success

    def decompile_concurrently(self, file_paths: list[Path]) -> Iterator[tuple[Path, Path, bool]]:
        # for file_path in file_paths:
        # yield file_path, self.working_directory / (file_path.name + self.output_dir_suffix), True
        yield from self.concurrent_executor.map(self.decompile, file_paths)

    def iter_decompiled_files(self, file_paths: list[Path]) -> Iterator[Path]:
        for file_path, output_dir, success in self.decompile_concurrently(file_paths):
            if success:
                yield from filter(Path.is_file, output_dir.rglob("*"))

    def remove_output_dir(self, output_dir: Path) -> Path:
        if output_dir.exists() and output_dir.is_dir():
            print(f"Removing decompiled directory: {output_dir}")
            rmtree(output_dir)
        return output_dir

    def remove_output_dirs(self):
        num_output_dirs = len(self.output_dirs)
        print(f"Removing {num_output_dirs} decompiled directories.")
        for output_dir in self.concurrent_executor.map(self.remove_output_dir, self.output_dirs.values()):
            print(f"Removed decompiled directory: {output_dir}")
        # self.output_dirs.clear()
        print(f"Done removing {num_output_dirs} decompiled directories.")


if __name__ == "__main__":
    decompiler = JavaDecompiler()
    file_paths = list(Path("/Users/lucasfaudman/Documents/SANS/SEC575/earn/apks").glob("*.apk"))[:2]
    for file_path, output_dir, success in decompiler.decompile_concurrently(file_paths):
        print("SUCCESS" if success else "FAILURE", output_dir)
