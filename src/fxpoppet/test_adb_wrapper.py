# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from subprocess import CompletedProcess, TimeoutExpired

from pytest import mark, raises

from .adb_wrapper import (
    ADBCommandError,
    ADBResult,
    ADBWrapper,
    _get_android_sdk,
)


def test_adb_wrapper_adb_check(mocker, tmp_path):
    """test ADBWrapper._adb_check()"""
    (tmp_path / "platform-tools").mkdir()
    fake_adb_sys = tmp_path / "platform-tools" / "adb-sys"
    fake_adb_sys.touch()
    fake_adb = tmp_path / "platform-tools" / "adb"
    fake_adb.touch()
    # use system adb
    mocker.patch("fxpoppet.adb_wrapper.ANDROID_SDK_ROOT", tmp_path / "missing")
    mocker.patch("fxpoppet.adb_wrapper.which", return_value=str(fake_adb_sys))
    assert ADBWrapper._adb_check() == str(fake_adb_sys)
    # use recommended adb
    mocker.patch("fxpoppet.adb_wrapper.ANDROID_SDK_ROOT", tmp_path)
    assert ADBWrapper._adb_check() == str(fake_adb)
    # adb not installed
    mocker.patch("fxpoppet.adb_wrapper.ANDROID_SDK_ROOT", tmp_path / "missing")
    mocker.patch("fxpoppet.adb_wrapper.which", return_value=None)
    with raises(OSError, match=r"Please install ADB"):
        assert ADBWrapper._adb_check()


@mark.parametrize(
    "env_var, os_name",
    [
        ("ANDROID_HOME", "Linux"),
        ("ANDROID_SDK_ROOT", "Linux"),
        ("LOCALAPPDATA", "Windows"),
        (None, "Darwin"),
        # default to ~/
        (None, "Linux"),
    ],
)
def test_get_android_sdk(mocker, tmp_path, env_var, os_name):
    """test _get_android_sdk()"""

    def _getenv(in_var, default=None):
        if in_var == env_var:
            return str(tmp_path)
        return default

    mocker.patch("fxpoppet.adb_wrapper.getenv", _getenv)
    mocker.patch("fxpoppet.adb_wrapper.system", return_value=os_name)
    assert _get_android_sdk()


@mark.parametrize(
    "serial, wait",
    [
        (None, False),
        ("device-1234", True),
    ],
)
def test_adb_wrapper_call(mocker, serial, wait):
    """test ADBWrapper.call() success"""
    fake_run = mocker.patch(
        "fxpoppet.adb_wrapper.run",
        return_value=CompletedProcess(["foo"], returncode=0, stdout=""),
    )
    mocker.patch("fxpoppet.adb_wrapper.getenv", return_value="1")
    adb = ADBWrapper("fake-adb")
    result = adb.call(["foo"], serial=serial, wait_for_device=wait)
    assert result
    if serial is not None:
        assert "-s" in fake_run.call_args.args[-1]
        assert "device-1234" in fake_run.call_args.args[-1]
    else:
        assert "-s" not in fake_run.call_args.args[-1]
        assert "device-1234" not in fake_run.call_args.args[-1]
    if wait:
        assert "wait-for-device" in fake_run.call_args.args[-1]
    else:
        assert "wait-for-device" not in fake_run.call_args.args[-1]


@mark.parametrize(
    "output, message",
    [
        ("Android Debug Bridge version", "Invalid ADB command"),
        ("adb: unknown command", "Invalid ADB command"),
        ("adb: usage:", "Invalid ADB command"),
        ("adb: more than one device/emulator", "Multiple devices detected"),
    ],
)
def test_adb_wrapper_call_command_error(mocker, output, message):
    """test ADBWrapper.call() command error"""
    mocker.patch(
        "fxpoppet.adb_wrapper.run",
        return_value=CompletedProcess(["foo"], returncode=1, stdout=output),
    )
    mocker.patch("fxpoppet.adb_wrapper.getenv", return_value="1")
    with raises(ADBCommandError, match=message):
        ADBWrapper("fake-adb").call(["foo"])


def test_adb_wrapper_call_timeout(mocker):
    """test ADBWrapper.call() timeout"""
    mocker.patch(
        "fxpoppet.adb_wrapper.run",
        side_effect=TimeoutExpired(["foo"], timeout=1),
    )
    mocker.patch("fxpoppet.adb_wrapper.getenv", return_value="1")
    adb = ADBWrapper("fake-adb")
    assert adb.call(["foo"]) is None


def test_adb_wrapper_devices_none(mocker):
    """test ADBWrapper.devices() no devices attached"""
    mocker.patch("fxpoppet.adb_wrapper.which", return_value="fake_bin")

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "devices":
            return ADBResult(1, "List of devices attached\n")
        raise AssertionError(f"unexpected command {cmd!r}")

    mocker.patch("fxpoppet.adb_wrapper.ADBWrapper.call", side_effect=fake_call)
    assert not ADBWrapper.devices(any_state=True)


@mark.parametrize(
    "any_state, count",
    [
        # all devices
        (True, 3),
        # filter devices that are not in state 'device'
        (False, 2),
    ],
)
def test_adb_wrapper_devices_multiple(mocker, any_state, count):
    """test ADBWrapper.devices() multiple devices attached"""
    mocker.patch("fxpoppet.adb_wrapper.which", return_value="fake_bin")

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "devices":
            return ADBResult(
                0,
                "List of devices attached\n"
                "* daemon not running; starting now at tcp:5037\n"
                "* daemon started successfully\n"
                "emulator-5554   device\n"
                "emulator-5556   offline\n"
                "emulator-5558   device\n",
            )
        raise AssertionError(f"unexpected command {cmd!r}")

    mocker.patch("fxpoppet.adb_wrapper.ADBWrapper.call", side_effect=fake_call)
    devices = ADBWrapper.devices(any_state=any_state)
    assert len(devices) == count
    assert "emulator-5554" in devices
    assert "emulator-5556" in devices if any_state else "emulator-5556" not in devices
    assert "emulator-5558" in devices
