import argparse
from pathlib import Path
from shutil import which
from typing import Optional

from decompiler import JavaDecompiler
# from .secret_scanner import SecretScanner

def main():
    parser = argparse.ArgumentParser(description="Decompile APK files and scan for secrets.")
    # parser.add_help = True
    parser.add_argument("-f", "--files", type=str, nargs="+", metavar="FILES_TO_SCAN", help="Path to APK file to decompile and scan.", required=True)
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



if __name__ == "__main__":
    main()
    
