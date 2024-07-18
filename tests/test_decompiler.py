import pytest
from pathlib import Path
from apkscan import Decompiler


@pytest.mark.parametrize(
    "test_apk",
    [
        "test-apk-1.apk",
        "test-xapk-1.xapk",
    ],
)
def test_decompile(tmpdir, test_apk):
    tmpdir_path = Path(tmpdir)
    decompiler = Decompiler(working_dir=tmpdir_path)
    test_apk_path = Path(__file__).parent / "test_apks" / test_apk
    binary_name_file_path = ("jadx", test_apk_path)
    file_path, output_dir, decompiled_files, success = decompiler.decompile(binary_name_file_path)
    assert file_path == test_apk_path
    assert (
        output_dir.exists()
        and output_dir.is_dir()
        and output_dir == tmpdir_path / (test_apk_path.stem + "-decompiled/jadx")
    )
    assert decompiled_files and all(
        decompiled_file.exists() and decompiled_file.is_file() for decompiled_file in decompiled_files
    )
    assert success
    decompiler.cleanup()
    assert not output_dir.exists()
