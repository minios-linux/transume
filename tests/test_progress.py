import pytest

from transume.progress import ProgressParser


def test_partclone_progress_line():
    event = ProgressParser().feed_line(
        "Elapsed: 00:01:02, Remaining: 00:00:20, Completed: 73.25%, Rate: 1.20GB/min"
    )
    assert event.kind == "progress"
    assert event.percent == 73.25
    assert event.rate == "1.20GB/min"


def test_generic_progress_and_stage_are_conservative():
    parser = ProgressParser()
    assert parser.feed_line("42% copied from /dev/sda1").percent == 42
    stage = parser.feed_line("Restoring partition /dev/sdb1")
    assert stage.kind == "stage"
    assert stage.device == "sdb1"
    assert stage.percent == 42


def test_invalid_percentage_is_rejected():
    with pytest.raises(ValueError):
        ProgressParser().feed_line("Completed 101%")


def test_ansi_control_sequences_are_removed():
    event = ProgressParser().feed_line("\x1b[1;33mChecking /dev/sda1\x1b[0;39m")
    assert event.message == "Checking /dev/sda1"


def test_blank_target_disk_label_is_non_fatal_warning():
    event = ProgressParser().feed_line("Error: /dev/sdc: unrecognised disk label")
    assert event.kind == "warning"
    assert event.device == "sdc"


def test_other_errors_remain_errors():
    event = ProgressParser().feed_line("Error: failed to restore /dev/sdc1")
    assert event.kind == "error"


def test_clonezilla_live_media_warning_is_normal_for_minios():
    event = ProgressParser().feed_line(
        "///WARNING/// filesystem.squashfs not found! No idea where is LIVE MEDIA!!!"
    )
    assert event.kind == "log"
    assert event.message == "Running in the MiniOS live environment."


def test_error_named_temporary_file_in_command_is_not_a_failure():
    event = ProgressParser().feed_line(
        "zstd -dc 2> /tmp/unzip_cmd_error.abc | partclone.ext4 -r"
    )
    assert event.kind == "log"
    assert ProgressParser().feed_line("Failed to save partition /dev/sda1").kind == "error"
