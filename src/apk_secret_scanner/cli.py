import argparse
from pathlib import Path
from shutil import which
from typing import Optional, Generator
from pprint import pprint

from decompiler import JavaDecompiler
from secret_scanner import SecretScanner, SecretResult

class JavaSecretScanner:
    def __init__(self, 
                 decompiler: JavaDecompiler, 
                 secret_scanner: SecretScanner,
                 keep_decompiled: bool = False,
                 keep_failed_decompiled: bool = False,                 
                 ):
        self.decompiler = decompiler
        self.secret_scanner = secret_scanner
        self.keep_decompiled = keep_decompiled
        self.keep_failed_decompiled = keep_failed_decompiled

    def decompile(self, file_paths: list[Path]) -> Generator[Path, None, None]:
        
        for file_path, decompiled_dir, success in self.decompiler.iterdecompile(file_paths):
            if success:
                print(f"Decompilation of {file_path} completed successfully.")
                yield from filter(Path.is_file, decompiled_dir.rglob("*"))
            else:
                print(f"Decompilation of {file_paths} failed.")

    def decompile_and_scan(self, file_paths: list[Path]) -> Generator[SecretResult, None, None]:
        print(f'BEGIN YIELD FROM')
        yield from self.secret_scanner.iterscan_files(self.decompile(file_paths))
        print(f'END YIELD FROM')
        if not self.keep_decompiled:
            self.decompiler.remove_decompiled_dirs()
            

            


def main():
    parser = argparse.ArgumentParser(description="Decompile APK files and scan for secrets.")
    parser.add_argument("-f", "--files", type=str, nargs="+", metavar="FILES_TO_SCAN", help="Path to APK file to decompile and scan.", required=False)
    parser.add_argument("-p", "--pattern", type=Path, metavar="SECRET_PATTERNS_FILE", help="Path to custom secrets patterns JSON.")
    parser.add_argument("-o", "--output-dir", type=Path, metavar="OUTPUT_DIR", default=Path.cwd(), help="Output directory for decompiled APK files.")    
    parser.add_argument("--format", type=str, choices=["json", "text"], default="json", help="Output format for results.")
    parser.add_argument("--keep-decompiled", action="store_true", help="Keep decompiled APK files after scanning.")
    parser.add_argument("--decompiler", type=Path, default=Path(which("jadx") or "/usr/local/bin/jadx"), help="Path to JADX decompiler binary.")    
    parser.add_argument("--decompiler-args", type=str, nargs="+", help="Additional arguments to pass to JADX.")
    parser.add_argument("--deobfuscate", action="store_true", help="Deobfuscate APK file.")
    parser.add_argument("--deobfuscation-arg", type=str, default="--deobf", help="Argument to pass to JADX for deobfuscation.")
    parser.add_argument("--output-dir-arg", type=str, default="--output-dir", help="Argument to pass to JADX for output directory.")
    parser.add_argument("--output-dir-prefix", type=str, default="decompiled-", help="Prefix for output directory.")
    args = parser.parse_args()

    decompiler = JavaDecompiler()
    secret_scanner = SecretScanner([Path(__file__).parent.parent.parent / 'secret-patterns/test.yaml'])
    apk_scanner = JavaSecretScanner(decompiler, secret_scanner)
    args.files = list(Path("/Users/lucasfaudman/Documents/SANS/SEC575/earn/apks").glob("*.apk"))[:2]
    results = []
    for secret_result in apk_scanner.decompile_and_scan(args.files):
        print(f"Found {secret_result.locator.name}: {secret_result.secret} in {secret_result.file.name} (line {secret_result.line_number})")
        results.append(secret_result)

    pprint(results)


if __name__ == "__main__":
    main()
    
