# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from pytest import mark

from .adb_device import ADBDevice
from .adb_wrapper import ADBResult, ADBWrapper


@mark.parametrize(
    "call_result",
    [
        ADBResult(0, "success"),
        ADBResult(1, "process failure"),
    ],
)
def test_adb_device_call_success(mocker, call_result):
    """test ADBDevice.call() success"""
    adb = mocker.Mock(spec_set=ADBWrapper)
    adb.call.return_value = call_result
    device = ADBDevice(adb, "fake-serial")
    result = device.call(["foo"])
    assert result
    assert result.exit_code == call_result.exit_code
    assert result.output == call_result.output
    assert device._connected


@mark.parametrize(
    "call_result",
    [
        None,
        ADBResult(1, "error: device offline"),
        ADBResult(1, "error: no devices/emulators found"),
        ADBResult(1, "error: closed"),
    ],
)
def test_adb_device_call_errors(mocker, call_result):
    """test ADBDevice.call() device connectivity errors"""
    adb = mocker.Mock(spec_set=ADBWrapper)
    adb.call.return_value = call_result
    device = ADBDevice(adb, "fake-serial")
    assert device.call(["foo"]) is None
    assert not device._connected


@mark.parametrize(
    "connected, device_call",
    [
        (True, ADBResult(0, "device")),
        (False, ADBResult(1, "")),
    ],
)
def test_adb_device_connect(mocker, connected, device_call):
    """test ADBDevice.connect()"""
    adb = mocker.patch("fxpoppet.adb_device.ADBWrapper").return_value
    adb.call.side_effect = (ADBResult(0, ""), device_call)
    device = ADBDevice.connect("test-1234", 10)
    assert device if connected else device is None


@mark.parametrize(
    "result, device_call",
    [
        ("device", ADBResult(0, "device")),
        ("offline", ADBResult(0, "offline")),
        (None, ADBResult(1, "error")),
    ],
)
def test_adb_device_state(mocker, result, device_call):
    """test ADBDevice.state()"""
    adb = mocker.Mock(spec_set=ADBWrapper)
    adb.call.return_value = device_call
    device = ADBDevice(adb, "test-1234")
    assert device.state() == result


def test_adb_device_call(mocker):
    """test ADBDevice.call()"""
    adb = mocker.Mock(spec_set=ADBWrapper)
    device = ADBDevice(adb, "test-1234")
    device.call(("args", "foo"), timeout=55, wait_for_device=True)
    assert adb.call.call_args.args[-1] == ("args", "foo")
    assert adb.call.call_args.kwargs.get("serial") == "test-1234"
    assert adb.call.call_args.kwargs.get("timeout") == 55
    assert adb.call.call_args.kwargs.get("wait_for_device") is True


@mark.parametrize(
    "result, device_call",
    [
        # success
        (True, ADBResult(0, "1")),
        # failed to boot
        (False, ADBResult(1, "")),
        # failed (no device)
        (False, None),
    ],
)
def test_adb_device_wait_for_boot(mocker, result, device_call):
    """test ADBDevice.wait_for_boot()"""
    mocker.patch("fxpoppet.adb_device.perf_counter", side_effect=range(10))
    mocker.patch("fxpoppet.adb_device.sleep")
    adb = mocker.Mock(spec_set=ADBWrapper)
    adb.call.return_value = device_call
    device = ADBDevice(adb, "test-1234")
    assert device.wait_for_boot(2) == result
