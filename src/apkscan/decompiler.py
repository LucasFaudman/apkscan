# © 2023 Lucas Faudman.
# Licensed under the MIT License (see LICENSE for details).
# For commercial use, see LICENSE for additional terms.
from subprocess import run, DEVNULL, SubprocessError
from pathlib import Path
from shutil import which, rmtree
from os import access, X_OK
from shlex import split as shlex_split
from typing import Optional, Iterator, Iterable, Literal

from enjarify import enjarify
from .concurrent_executor import ConcurrentExecutor

class Decompiler:
    CONFIG = {
        "jadx": {
            "binary": which("jadx") or "/usr/local/bin/jadx",
            "output_arg": "--output-dir",
            "deobf_arg": "--deobf",
            "extra_args": [],
            "file_exts": {".apk", ".xapk", ".jar", ".dex", ".class", ".smali", ".zip", ".aar", ".arsc", ".aab", ".jadx.kts"}
        },
        "apktool": {
            "binary": which("apktool") or "/usr/local/bin/apktool",
            "output_arg": "--output",
            "deobf_arg": "--force-manifest",
            "extra_args": ["d", "--force", "--keep-broken-res"],
            "file_exts": {".apk", ".xapk"}
        },
        "procyon": {
            "binary": which("procyon-decompiler") or "/usr/local/bin/procyon-decompiler",
            "output_arg": "-o",
            "deobf_arg": "-renames",
            "extra_args": [],
            "file_exts": {".jar", ".dex", ".class"}
        },
        "cfr": {
            "binary": which("cfr-decompiler") or "/usr/local/bin/cfr-decompiler",
            "output_arg": "--outputdir",
            "deobf_arg": "--antiobf",
            "extra_args": [],
            "file_exts": {".jar", "dex", "class"}
        },
        "krakatau": {
            "binary": which("krakatau") or "/usr/local/bin/krakatau",
            "output_arg": "--out",
            "deobf_arg": "",
            "extra_args": ["dis"],
            "file_exts": {".jar", ".zip", ".class"}
        },
        "fernflower": {
            "binary": which("fernflower") or "/usr/local/bin/fernflower",
            "output_arg": "",
            "deobf_arg": "",
            "extra_args": [],
            "file_exts": {".jar", ".class"}
        }
    }

    def __init__(
        self,
        binaries: Optional[dict[str, Optional[Path|str]]|Iterable[str]] = None,
        enjarify_choice: Literal["auto", "never", "always"] = "auto",
        deobfuscate: bool = False,
        extra_args: Optional[list[str]] = None,
        output_suffix: str = "-decompiled",
        working_dir: Path = Path("/tmp/apk-secret-scanner"),
        overwrite: bool = False,
        remove_failed_output_dirs: bool = True,
        suppress_output: bool = False,
        **concurrent_executor_kwargs,
    ):
        self.binary_paths = self.validate_binary_paths(binaries)
        self.enjarify = self.validate_enjarify_choice(enjarify_choice)
        self.deobfuscate = deobfuscate
        self.extra_args = self.validate_extra_args(extra_args)
        self.output_suffix = output_suffix
        self.working_dir = working_dir
        self.overwrite = overwrite
        self.remove_failed_output_dirs = remove_failed_output_dirs
        self.suppress_output = suppress_output
        self.concurrent_executor = ConcurrentExecutor(**{"concurrency_type": "thread", **concurrent_executor_kwargs})
        self.output_dirs = {}

    def validate_binary_paths(self, binaries: Optional[dict[str, Optional[Path|str]]|Iterable[str]]) -> dict[str, Path]:
        if not binaries:
            # Use JADX binary by default if no binaries specified
            jadx_path = self.CONFIG["jadx"]["binary"]
            print(f"No decompiler binaries specified. Defaulting to JADX binary at {jadx_path}.")
            binaries = {"jadx": jadx_path}

        if not isinstance(binaries, dict):
            # Handle any iterable of binary names
            binaries = dict.fromkeys(binaries)

        binary_paths = {}
        for binary_name, binary_path in binaries.items():
            binary_path =  Path(binary_path or self.CONFIG[binary_name]["binary"])
            if not binary_path.exists():
                print(f"Skipping {binary_name}. Binary not found: {binary_path}")
                print(f"Use --{binary_name} <PATH> to specify the path to the binary.")
                continue
            elif not access(binary_path, X_OK):
                print(f"Skipping {binary_name}. Binary not executable: {binary_path}")
                print(f"Use chmod +x {binary_path} to make it executable.")
                continue

            print(f"Found {binary_name} binary: {binary_path}")
            binary_paths[binary_name] = binary_path

        if not binary_paths:
            raise FileNotFoundError("No valid decompiler binaries found.")

        return binary_paths

    def num_binaries_to_run_on_ext(self, file_ext: str) -> int:
        return sum(1 for binary_name in self.binary_paths if file_ext in self.CONFIG[binary_name]["file_exts"])

    def validate_enjarify_choice(self, enjarify_choice: Literal["auto", "never", "always"]) -> bool:
        enjarify_needed = set(self.binary_paths) - {"jadx", "apktool"}
        if enjarify_choice == "auto":
            enjarify = bool(enjarify_needed)
        else:
            enjarify = enjarify_choice == "always"

        if enjarify_needed and not enjarify:
            raise ValueError(f"Enjarify is needed for {enjarify_needed} but enjarify_choice is {enjarify_choice}.")

        return enjarify

    def validate_extra_args(self, extra_args: Optional[list[str]]) -> dict[str, list[str]]:
        extra_args_dict = {binary_name: self.CONFIG[binary_name]["extra_args"] for binary_name in self.binary_paths}
        if not extra_args:
            return extra_args_dict
        for extra_arg in extra_args:
            binary_name, *args = shlex_split(extra_arg)
            if binary_name not in self.binary_paths:
                print(f"Skipping extra args for {binary_name}. Binary not found.")
                continue
            extra_args_dict[binary_name] = args
        return extra_args_dict


    def make_args(self, binary_name: str, file_path: Path, output_path: Path) -> list[str]:
        args = [self.binary_paths[binary_name], *self.extra_args.get(binary_name, ()), self.CONFIG[binary_name]["output_arg"], output_path]
        if self.deobfuscate and (deobf_arg := self.CONFIG[binary_name].get("deobf_arg")) and deobf_arg not in args:
            args.append(deobf_arg)
        args.append(file_path)
        return list(map(str, args))


    def try_run_binary(self, binary_name: str, file_path: Path, output_path: Path) -> bool:
        args = self.make_args(binary_name, file_path, output_path)
        kwargs = {"stdout": DEVNULL, "stderr": DEVNULL} if self.suppress_output else {}
        kwargs["check"] = False
        try:
            print(f"Running {binary_name} on {file_path.name}")
            result = run(args, **kwargs) # type: ignore
            return True
        except SubprocessError as e:
            print(f"Error Running {binary_name} on {file_path.name}: {e}")
            return False

    def get_output_dir(self, file_path: Path) -> Path:
        output_dir = self.working_dir / (file_path.stem + self.output_suffix)
        self.output_dirs[file_path.stem] = output_dir
        if not output_dir.exists():
            print(f"Creating output directory: {output_dir}")
            output_dir.mkdir(parents=True, exist_ok=True)
            print(f"Output directory created: {output_dir}")
        return output_dir

    def enjarify_file(self, file_path: Path) -> Path:
        if file_path.suffix not in {".apk", ".dex"}:
            print(f"Skipping {file_path.name}. Enjarify only works on .apk and .dex files.")
            return file_path

        jar_file = (self.get_output_dir(file_path) / file_path.stem).with_suffix(".jar")
        if jar_file.exists() and not self.overwrite:
            return jar_file

        try:
            print(f"\nEnjarifying {file_path.name} to {jar_file.name}")
            enjarify(file_path, jar_file, overwrite=True, quiet=self.suppress_output)
            print(f"Successfully enjarified {file_path.name} to {jar_file}")
        except Exception as e:
            print(f"Error enjarifying {file_path.name}: {e}")
            jar_file.unlink(missing_ok=True)

        return jar_file

    def decompile(self, binary_name_file_path: tuple[str, Path]) -> tuple[Path, Path, Optional[set[Path]], bool]:
        binary_name, file_path = binary_name_file_path
        output_dir = self.get_output_dir(file_path) / binary_name
        if output_dir.exists() and not self.overwrite:
            success = True
        else:
            output_dir.mkdir(parents=True, exist_ok=True)
            success = self.try_run_binary(binary_name, file_path, output_dir)

        if success:
            print(f"Successfully decompiled {file_path.name} with {binary_name}")
        elif self.remove_failed_output_dirs:
            print(f"Erorr decompiling {file_path.name} with {binary_name}.")
            self.remove_output_dir(output_dir)

        if success or not self.remove_failed_output_dirs:
            print(f"\nIndexing decompiled files in {output_dir}...")
            decompiled_files = set((*filter(Path.is_file, output_dir.rglob("*")),))
            print(f"Found {len(decompiled_files)} decompiled files for {file_path.name}")
        else:
            decompiled_files = None

        return file_path, output_dir, decompiled_files, success

    def enjarify_concurrently(self, file_paths: Iterable[Path]) -> Iterator[Path]:
        yield from self.concurrent_executor.map(self.enjarify_file, file_paths)

    def binary_name_file_path_generator(self, file_paths: Iterable[Path]) -> Iterator[tuple[str, Path]]:
        file_paths_generator = self.enjarify_concurrently(file_paths) if self.enjarify else file_paths
        for file_path in file_paths_generator:
            for binary_name in self.binary_paths:
                if file_path.suffix in self.CONFIG[binary_name]["file_exts"]:
                    yield binary_name, file_path

    def decompile_concurrently(self, file_paths: Iterable[Path]) -> Iterator[tuple[Path, Path, Optional[set[Path]], bool]]:
        yield from self.concurrent_executor.map(self.decompile, self.binary_name_file_path_generator(file_paths))

    def remove_output_dir(self, output_dir: Path) -> Path:
        if output_dir.exists() and output_dir.is_dir():
            print(f"Removing: {output_dir}")
            rmtree(output_dir)
        return output_dir

    def cleanup(self, **concurrency_kwargs):
        output_dirs = list(self.output_dirs.values())
        print(f"\nRemoving {len(output_dirs)} decompiled output directories...")
        for output_dir in self.concurrent_executor.map(
            self.remove_output_dir, output_dirs, **concurrency_kwargs):
            print(f"Removed: {output_dir}")
        print(f"Done removing {len(output_dirs)} decompiled output directories.")

    # def unpack_xapk(self, file_path: Path) -> Iterator[Path]:
        # TODO: Implement unpacking xapk files and place in front of decompilation when file is xapk
        # pass

    def __repr__(self) -> str:
        return f"Decompiler:(binary_paths={self.binary_paths}, extra_args={self.extra_args}, deobfuscate={self.deobfuscate}, output_suffix={self.output_suffix}, working_dir={self.working_dir}, remove_failed_output_dirs={self.remove_failed_output_dirs}, concurrent_executor={self.concurrent_executor})"
