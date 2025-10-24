# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import annotations

from logging import getLogger
from time import perf_counter, sleep
from typing import TYPE_CHECKING

from .adb_wrapper import ADBResult, ADBWrapper

if TYPE_CHECKING:
    from collections.abc import Sequence


LOG = getLogger(__name__)


class ADBDevice:
    """Android device.

    Attributes:
        _connected: Device is available for communication via ADB.
        adb: ADB interface.
        serial: Serial of Android device to use.
    """

    __slots__ = ("_connected", "adb", "serial")

    def __init__(self, adb: ADBWrapper, serial: str) -> None:
        self._connected = True
        self.adb = adb
        self.serial = serial

    def call(
        self,
        args: Sequence[str],
        timeout: int = 60,
        wait_for_device: bool = False,
    ) -> ADBResult | None:
        """Call ADB with provided arguments.

        Args:
            args: Arguments to pass to ADB.
            timeout: Seconds to wait for ADB call to complete.
            wait_for_device: Wait until device is ready to accept commands.

        Returns:
            Exit code and output of ADB call or None if the connection failed.
        """
        assert args
        if self._connected:
            error: str | None = None
            result = self.adb.call(
                args,
                serial=self.serial,
                timeout=timeout,
                wait_for_device=wait_for_device,
            )
            if result is None:
                error = "timeout"
            elif result.exit_code != 0:
                # check for device connectivity errors
                if result.output.startswith("error: device offline"):
                    error = "device offline"
                if result.output.startswith("error: no devices/emulators found"):
                    error = "device not found"
                if result.output.startswith("error: closed"):
                    error = "device closed"
            if error is None:
                return result
            LOG.error("Device connection failed (%s): %s", self.serial, error)
            self._connected = False
        return None

    @classmethod
    def connect(cls, serial: str, timeout: int) -> ADBDevice | None:
        """Attempt to connect to an Android device.

        Args:
            serial: Serial of Android device to connect to.
            timeout: Seconds to wait for ADB call to complete.

        Returns:
            ADBDevice object if successful otherwise None.
        """
        assert timeout >= 0
        adb = ADBWrapper()
        adb.call(("wait-for-device",), serial=serial, timeout=timeout)
        device = cls(adb, serial)
        return device if device.state() == "device" else None

    def shell(
        self,
        args: Sequence[str],
        timeout: int = 60,
        wait_for_device: bool = False,
    ) -> ADBResult | None:
        """Execute an ADB shell command via a non-interactive shell.

        Args:
            args: Arguments to pass when calling shell.
            timeout: Seconds to wait for call to complete.
            wait_for_device: Wait until device is ready to accept commands.

        Returns:
            Exit code and output of ADB call or None if the connection failed.
        """
        assert args
        return self.call(
            ("shell", "-T", "-n", *args),
            timeout=timeout,
            wait_for_device=wait_for_device,
        )

    def state(self) -> str | None:
        """Get device state.

        Args:
            None

        Returns:
            Device state if the device is available otherwise None.
        """
        result = self.call(("get-state",))
        return result.output if result and result.exit_code == 0 else None

    def wait_for_boot(self, timeout: float, poll_wait: int = 1) -> bool:
        """Wait for device to boot.

        Args:
            timeout: Time in seconds to wait for device to boot.
            poll_wait: Time in seconds between checks.

        Returns:
            True if device has booted successfully otherwise False.
        """
        deadline = perf_counter() + timeout
        cmd = ("getprop", "sys.boot_completed")
        while True:
            result = self.shell(cmd, timeout=10)
            if result and result.output == "1":
                return True
            if perf_counter() >= deadline:
                break
            sleep(poll_wait)
        return False
