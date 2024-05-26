from subprocess import run, CompletedProcess, SubprocessError
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from tempfile import mkdtemp
from typing import Optional

class JavaDecompiler:
    def __init__(self, 
                 decompiler_binary: Path = Path("/usr/local/bin/jadx"),                 
                 decompiler_args: Optional[list[str]] = None,
                 deobfuscate: bool = False,
                 deobfuscation_arg: str = "--deobf",
                 output_dir_arg: str = "--output-dir",
                 output_dir_prefix: str = "decompiled-",
                 ):
        
        self.decompiler_binary = decompiler_binary
        self.decompiler_args = decompiler_args if decompiler_args is not None else []
        self.deobfuscate = deobfuscate
        self.deobfuscation_arg = deobfuscation_arg
        self.output_dir_arg = output_dir_arg
        self.output_dir_prefix = output_dir_prefix


    def decompile(self, file_path: Path, output_dir: Optional[Path] = None) -> tuple[CompletedProcess|SubprocessError, Path]:
        if output_dir is None:
            print(f"No output directory specified for {file_path}. Creating temporary directory.")
            output_dir = Path(mkdtemp(prefix=self.output_dir_prefix))
            print(f"Temporary directory created: {output_dir}")
        if not output_dir.exists():
            print(f"Creating output directory: {output_dir}")
            output_dir.mkdir()
            print(f"Output directory created: {output_dir}")
        
        decompiler_args = [str(file_path), self.output_dir_arg, str(output_dir)] + self.decompiler_args
        if self.decompiler_args:
            decompiler_args.extend(self.decompiler_args)
        if self.deobfuscate:
            decompiler_args.append(self.deobfuscation_arg)

        try:
            print(f"Running {self.decompiler_binary.name} decompiler on {file_path}")
            result = run(decompiler_args, executable=str(self.decompiler_binary), check=True)
            print(f"Decompilation of {file_path} completed successfully.")
            return result, output_dir
        except SubprocessError as e:
            print(f"Error decompiling {file_path}: {e}")
            return e, output_dir

