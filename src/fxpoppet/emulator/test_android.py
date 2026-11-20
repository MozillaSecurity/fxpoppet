# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from subprocess import TimeoutExpired

from pytest import mark

from fxpoppet.emulator.android import main


@mark.parametrize(
    "wait_effect, kills",
    [
        # emulator exits after terminate()
        ((KeyboardInterrupt, 0), 0),
        # emulator does not exit after terminate() and is killed
        ((KeyboardInterrupt, TimeoutExpired("emu", 60), -9), 1),
        # emulator does not exit after kill()
        (
            (KeyboardInterrupt, TimeoutExpired("emu", 60), TimeoutExpired("emu", 10)),
            1,
        ),
    ],
)
def test_emulator_main_shutdown(mocker, wait_effect, kills):
    """test emulator main() shutdown handling"""
    emu_cls = mocker.patch("fxpoppet.emulator.android.AndroidEmulator", autospec=True)
    emu_cls.search_free_ports.return_value = 5554
    emu = emu_cls.return_value
    emu.pid = 1234
    emu.system_version.return_value = None
    emu.cpu_count.return_value = None
    emu.memory_usage.return_value = None
    emu.disk_usage.return_value = None
    emu.poll.return_value = None
    emu.wait.side_effect = wait_effect
    main(["--skip-dl"])
    assert emu.terminate.call_count == 1
    assert emu.kill.call_count == kills
    assert emu.wait.call_count == len(wait_effect)
    # the AVD is only removed once the emulator has been stopped
    assert emu.cleanup.call_count == 1
    emu_cls.remove_avd.assert_called_once_with("x86.5554")
