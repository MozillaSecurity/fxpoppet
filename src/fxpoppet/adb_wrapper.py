# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
from logging import getLogger
from os import getenv
from pathlib import Path
from platform import system
from shutil import which
from subprocess import PIPE, STDOUT, TimeoutExpired, run
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


LOG = getLogger(__name__)


def _get_android_sdk() -> Path:
    if getenv("ANDROID_HOME") is not None:
        android_home = Path(getenv("ANDROID_HOME", ""))
        if android_home.is_dir():
            return android_home
    if getenv("ANDROID_SDK_ROOT") is not None:
        return Path(getenv("ANDROID_SDK_ROOT", ""))
    if system() == "Windows" and getenv("LOCALAPPDATA") is not None:
        return Path(getenv("LOCALAPPDATA", "")) / "Android" / "sdk"
    if system() == "Darwin":
        return Path.home() / "Library" / "Android" / "sdk"
    return Path.home() / "Android" / "Sdk"


ANDROID_SDK_ROOT = _get_android_sdk()


class ADBCommandError(Exception):
    """ADB command is invalid or unrecognized"""


@dataclass(eq=False, frozen=True)
class ADBResult:
    """Results from an ADB call."""

    exit_code: int
    output: str


class ADBWrapper:
    """Android Debug Bridge (ADB) wrapper.

    Attributes:
        _adb_bin: ADB binary to use.
        _debug: Display call args and output. This can generate a lot of extra output.
    """

    __slots__ = ("_adb_bin", "_debug")

    def __init__(self, binary: str | None = None) -> None:
        self._adb_bin = binary or self._adb_check()
        self._debug = getenv("SHOW_ADB_DEBUG", "0") != "0"

    @staticmethod
    def _adb_check() -> str:
        """Find ADB binary. An OSError is raised if the ADB executable is not found.

        Args:
            None

        Returns:
            ADB binary.
        """
        sdk_bin = ANDROID_SDK_ROOT / "platform-tools" / "adb"
        if sdk_bin.is_file():
            LOG.debug("using recommended adb from '%s'", sdk_bin)
            return str(sdk_bin)
        installed_bin = which("adb")
        if installed_bin is None:
            raise OSError("Please install ADB")
        # TODO: update this to check adb version
        LOG.warning("Using adb binary from '%s'", installed_bin)
        LOG.warning("You are not using the recommended ADB install!")
        LOG.warning("Either run the setup script or proceed with caution.")
        return installed_bin

    def call(
        self,
        args: Sequence[str],
        serial: str | None = None,
        timeout: int = 10,
        wait_for_device: bool = False,
    ) -> ADBResult | None:
        """Wrapper to make calls to ADB. Launches ADB in a subprocess and collects
        output. If timeout is specified and elapses the ADB subprocess is terminated.

        Args:
            args: Arguments to pass to ADB.
            serial: Serial of Android device to send the command.
                Required if multiple devices are connected.
            timeout: Number of seconds to wait for ADB command to complete.
            wait_for_device: Wait until device is ready to accept commands.

        Returns:
            ADBResult if call completes before the timeout expires or None.
        """
        cmd = [self._adb_bin]
        if serial is not None:
            cmd.extend(("-s", serial))
        if wait_for_device:
            cmd.append("wait-for-device")
        cmd.extend(args)
        if self._debug:
            LOG.debug("call '%s' (%d)", " ".join(args), timeout)
        with suppress(TimeoutExpired):
            result = run(
                cmd,
                check=False,
                encoding="utf-8",
                errors="replace",
                stderr=STDOUT,
                stdout=PIPE,
                timeout=timeout,
            )
            if self._debug:
                LOG.debug(
                    "=== adb start ===\n%s\n=== adb end, returned %d ===",
                    result.stdout,
                    result.returncode,
                )
            if result.returncode != 0:
                if result.stdout.startswith("adb: more than one device/emulator"):
                    raise ADBCommandError("Multiple devices detected")
                if (
                    result.stdout.startswith("Android Debug Bridge version")
                    or result.stdout.startswith("adb: unknown command")
                    or result.stdout.startswith("adb: usage:")
                ):
                    LOG.error("Invalid ADB command: '%s'", " ".join(cmd))
                    LOG.debug("ADB output:\n%s", result.stdout)
                    raise ADBCommandError("Invalid ADB command")
            return ADBResult(result.returncode, result.stdout.strip())
        return None

    @classmethod
    def devices(cls, any_state: bool = True) -> dict[str, str]:
        """Devices visible to ADB.

        Args:
            any_state: Include devices in a state other than "device".

        Returns:
            A mapping of devices and their state.
        """
        result = cls().call(("devices",), timeout=30)
        devices: dict[str, str] = {}
        if result is None or result.exit_code != 0:
            return devices
        # skip header on the first line
        for entry in result.output.splitlines()[1:]:
            try:
                name, state = entry.split()
            except ValueError:
                continue
            if not any_state and state != "device":
                continue
            devices[name] = state
        return devices
