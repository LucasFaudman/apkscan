from subprocess import run, SubprocessError
from pathlib import Path
from shutil import which, rmtree
from typing import Optional, Iterator, Iterable

from .concurrent_executor import ConcurrentExecutor

class JavaDecompiler:
    def __init__(
        self,
        binary: Path = Path(which("jadx") or "/usr/local/bin/jadx"),
        extra_args: Optional[list[str]] = None,
        deobfuscate: bool = False,
        deobf_arg: str = "--deobf",
        output_arg: str = "--output-dir",
        output_suffix: str = "-decompiled",
        working_dir: Path = Path("/tmp/apk-secret-scanner"),
        remove_failed_output_dirs: bool = True,
        **concurrent_executor_kwargs,
    ):
        self.binary = binary
        self.extra_args = extra_args if extra_args is not None else []
        self.deobfuscate = deobfuscate
        self.deobf_arg = deobf_arg
        self.output_arg = output_arg
        self.output_suffix = output_suffix
        self.working_dir = working_dir
        self.remove_failed_output_dirs = remove_failed_output_dirs
        self.output_dirs = {}
        self.concurrent_executor = ConcurrentExecutor(**{"concurrency_type": "thread", **concurrent_executor_kwargs})

    def decompile(self, file_path: Path) -> tuple[Path, Path, bool]:
        file_name = file_path.name
        output_dir = self.working_dir / (file_name + self.output_suffix)
        self.output_dirs[file_path] = output_dir
        if not output_dir.exists():
            print(f"Creating output directory: {output_dir}")
            output_dir.mkdir(parents=True, exist_ok=True)
            print(f"Output directory created: {output_dir}")

        decompiler_args = [self.binary, file_path, self.output_arg, output_dir] + self.extra_args

        if self.deobfuscate and self.deobf_arg not in decompiler_args:
            decompiler_args.append(self.deobf_arg)

        try:
            print(f"Running {self.binary.name} decompiler on {file_name}")
            result = run(list(map(str, decompiler_args)), capture_output=False)
            success = result.returncode == 0
            print(f"Successfully decompiled {file_name} to {output_dir}")
        except SubprocessError as e:
            print(f"Error decompiling {file_name}: {e}")
            success = False
            if self.remove_failed_output_dirs:
                self.remove_output_dir(output_dir)

        return file_path, output_dir, success

    def decompile_concurrently(self, file_paths: Iterable[Path]) -> Iterator[tuple[Path, Path, bool]]:
        yield from self.concurrent_executor.map(self.decompile, file_paths)

    def remove_output_dir(self, output_dir: Path) -> Path:
        if output_dir.exists() and output_dir.is_dir():
            print(f"Removing: {output_dir}")
            rmtree(output_dir)
        return output_dir

    def remove_output_dirs(self):
        num_removed = 0
        for output_dir in self.concurrent_executor.map(self.remove_output_dir, self.output_dirs.values()):
            num_removed += 1
            print(f"Removed: {output_dir}")
        print(f"Done removing {num_removed} decompiled output directories.")

    def __repr__(self) -> str:
        return f"JavaDecompiler(binary={self.binary}, extra_args={self.extra_args}, deobfuscate={self.deobfuscate}, deobf_arg={self.deobf_arg}, output_arg={self.output_arg}, output_suffix={self.output_suffix}, working_dir={self.working_dir}, remove_failed_output_dirs={self.remove_failed_output_dirs}, concurrent_executor={self.concurrent_executor})"
