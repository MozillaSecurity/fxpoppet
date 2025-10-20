# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
from logging import getLogger
from os import getenv
from pathlib import Path, PurePosixPath
from platform import system
from shutil import which
from subprocess import PIPE, STDOUT, TimeoutExpired, check_output, run
from tempfile import TemporaryDirectory
from time import sleep, time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable, Mapping, Sequence


LOG = getLogger(__name__)

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


@dataclass(eq=False, frozen=True)
class ADBResult:
    """Results from an ADB call."""

    exit_code: int
    output: str


@dataclass(eq=False, frozen=True)
class DeviceProcessInfo:
    """Details of a process on the connected device."""

    memory: int
    name: str
    pid: int
    ppid: int


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


AAPT_BIN: str | None = None
ADB_BIN: str | None = None
ANDROID_SDK_ROOT = _get_android_sdk()
DEVICE_TMP = PurePosixPath("/data/local/tmp")


class ADBCommandError(Exception):
    """ADB command is invalid or unrecognized"""


class ADBCommunicationError(Exception):
    """ADB failed to communicate with the device"""


class ADBSessionError(Exception):
    """Operation failed unexpectedly or session state is invalid"""


# pylint: disable=too-many-public-methods
class ADBSession:
    """ADB Session management.

    Attributes:
        _debug_adb: Include ADB output in debug output.
        _root: Connected as root user.
        connected: ADB connection state.
        device_id: Unique Android ID.
        symbols: Location of symbols on the local machine.
    """

    __slots__ = (
        "_debug_adb",
        "_root",
        "_serial",
        "connected",
        "device_id",
        "symbols",
    )

    def __init__(self, serial: str) -> None:
        self._debug_adb = getenv("SHOW_ADB_DEBUG", "0") != "0"
        self._root = False
        self._serial = serial
        self.connected = False
        self.device_id: str | None = None
        self.symbols: dict[str, Path] = {}

    @staticmethod
    def _aapt_check() -> str:
        """Find Android Asset Packaging Tool (AAPT).
        An OSError is raised if the AAPT executable is not found.

        Args:
            None

        Returns:
            AAPT binary.
        """
        # pylint: disable=global-statement
        global AAPT_BIN
        if AAPT_BIN is None:
            skd_bin = ANDROID_SDK_ROOT / "android-9" / "aapt"
            if skd_bin.is_file():
                LOG.debug("using recommended aapt from '%s'", skd_bin)
                AAPT_BIN = str(skd_bin)
            else:
                installed_bin = which("aapt")
                if installed_bin is None:
                    raise OSError("Please install AAPT")
                # TODO: update this to check aapt version
                LOG.warning("Using aapt binary from '%s'", installed_bin)
                AAPT_BIN = installed_bin
        return AAPT_BIN

    @staticmethod
    def _adb_check() -> str:
        """Find Android Debug Bridge (ADB).
        An OSError is raised if the ADB executable is not found.

        Args:
            None

        Returns:
            ADB binary.
        """
        # pylint: disable=global-statement
        global ADB_BIN
        if ADB_BIN is None:
            sdk_bin = ANDROID_SDK_ROOT / "platform-tools" / "adb"
            if sdk_bin.is_file():
                LOG.debug("using recommended adb from '%s'", sdk_bin)
                ADB_BIN = str(sdk_bin)
            else:
                installed_bin = which("adb")
                if installed_bin is None:
                    raise OSError("Please install ADB")
                # TODO: update this to check adb version
                LOG.warning("Using adb binary from '%s'", installed_bin)
                LOG.warning("You are not using the recommended ADB install!")
                LOG.warning("Either run the setup script or proceed with caution.")
                ADB_BIN = installed_bin
        return ADB_BIN

    @classmethod
    def _call_adb(
        cls, cmd: Sequence[str], timeout: int = 10, serial: str | None = None
    ) -> ADBResult:
        """Wrapper to make calls to ADB. Launches ADB in a subprocess and collects
        output. If timeout is specified and elapses the ADB subprocess is terminated.
        This function is only meant to be called directly by ADBSession.call().

        Args:
            cmd: Full ADB command.
            timeout: Seconds to wait for ADB command to complete.
            serial: Serial of Android device to connect to.

        Returns:
            Exit code and stderr, stdout of ADB call.
        """
        adb = cls._adb_check()
        try:
            result = run(
                (adb, "-s", serial, *cmd) if serial else (adb, *cmd),
                check=False,
                encoding="utf-8",
                errors="replace",
                stderr=STDOUT,
                stdout=PIPE,
                timeout=timeout,
            )
        except TimeoutExpired:
            LOG.warning("ADB call timed out!")
            return ADBResult(1, "")
        return ADBResult(result.returncode, result.stdout.strip())

    def _get_procs(
        self, pid: int | None = None, pid_children: int | None = None
    ) -> Generator[DeviceProcessInfo]:
        """Provides a DeviceProcessInfo object for each process running on the connected
        device by default. pid and pid_children can be used to filter the results.

        Args:
            pid: Process ID to include in lookup.
            pid_children: Used to lookup the children of the given PID.

        Yields:
            Process information.
        """
        cmd = ["ps", "-o", "pid,ppid,rss,name"]
        if pid is not None:
            cmd.append(str(pid))
        if pid_children is not None:
            cmd.extend(("--ppid", str(pid_children)))
        if not pid and not pid_children:
            cmd.append("-A")
        for line in self.shell(cmd, timeout=30).output.splitlines()[1:]:
            try:
                proc_id, ppid, memory, name = line.split()
                yield DeviceProcessInfo(int(memory), name, int(proc_id), int(ppid))
            except ValueError:  # noqa: PERF203
                LOG.debug("failed to parse ps line '%s'", line)

    @property
    def airplane_mode(self) -> bool:
        """Get the current state of airplane mode.

        Args:
            None

        Returns:
            True if airplane mode is enabled otherwise False.
        """
        return self.shell(
            ["settings", "get", "global", "airplane_mode_on"]
        ).output.startswith("1")

    @airplane_mode.setter
    def airplane_mode(self, state: bool) -> None:
        """Enable/disable airplane mode.

        Args:
            state: True will enable and False will disable airplane mode.

        Returns:
            None
        """
        self.shell(
            ["settings", "put", "global", "airplane_mode_on", ("1" if state else "0")]
        )
        self.shell(
            [
                "su",
                "root",
                "am",
                "broadcast",
                "-a",
                "android.intent.action.AIRPLANE_MODE",
            ]
        )

    def call(
        self, args: Sequence[str], device_required: bool = True, timeout: int = 120
    ) -> ADBResult:
        """Call ADB with provided arguments.

        Args:
            args: Arguments to pass to ADB.
            device_required: A device must be available.
            timeout: Seconds to wait for ADB call to complete.

        Returns:
            Exit code and stderr, stdout of ADB call.
        """
        assert args
        if self._debug_adb:
            LOG.debug("call '%s' (%d)", " ".join(args), timeout)
        # a few adb commands do not require a connection
        if not self.connected and args[0] not in {"connect", "devices", "disconnect"}:
            raise ADBCommunicationError("ADB session is not connected!")
        result = self._call_adb(args, timeout=timeout, serial=self._serial)
        if self._debug_adb:
            LOG.debug(
                "=== adb start ===\n%s\n=== adb end, returned %d ===",
                result.output,
                result.exit_code,
            )
        if result.exit_code != 0:
            if result.output.startswith("Android Debug Bridge version"):
                raise ADBCommandError(f"Invalid ADB command '{' '.join(args)}'")
            if result.output.startswith("adb: usage:"):
                raise ADBCommandError(result.output)
            if device_required:
                if result.output.startswith("error: device offline"):
                    LOG.error("ADB call failed: device offline (%s)", self.device_id)
                    raise ADBCommunicationError("Device offline")
                if result.output.startswith("error: no devices/emulators found"):
                    LOG.error("ADB call failed: device not found (%s)", self.device_id)
                    raise ADBCommunicationError("Device not found")
                if result.output.startswith("error: closed"):
                    LOG.error("ADB call failed: device closed (%s)", self.device_id)
                    raise ADBCommunicationError("Device closed")
            if result.exit_code != 1:
                LOG.warning("ADB exit code: %d", result.exit_code)
        return result

    def clear_logs(self) -> bool:
        """Call 'adb logcat --clear' to wipe logs.

        Args:
            None

        Returns:
            True if logs were cleared otherwise False.
        """
        return self.call(["logcat", "--clear"], timeout=10).exit_code == 0

    def collect_logs(self, pid: int | None = None) -> str:
        """Collect logs from device with logcat.

        Args:
            pid: Process ID to collect logs from. If pid is None Logs from all
                 processes will be collected.

        Returns:
            Logcat output.
        """
        LOG.debug("collect_logs()")
        if not self.connected:
            LOG.debug("device not connected cannot collect logs")
            # TODO: return None if disconnected?
            return ""
        cmd = ["logcat", "-d", "*:I"]
        if pid is not None:
            cmd.append(f"--pid={pid}")
        return self.call(cmd, timeout=30).output

    def connect(self, as_root: bool = True, boot_timeout: int = 300) -> None:
        """Connect to a device via ADB.

        Args:
            as_root: Attempt to enable root. Default is True.
            boot_timeout: Seconds to wait for device boot to complete.

        Returns:
            None.
        """
        assert boot_timeout > 0
        retry = True
        root_called = False
        set_enforce_called = False
        while retry:
            retry = False
            self.connected = True
            # verify we are connected
            LOG.debug("waiting for '%s' to boot (%ds)...", self._serial, boot_timeout)
            if not self.wait_for_boot(timeout=boot_timeout):
                LOG.debug("device failed to boot (%ds)", boot_timeout)
                self.connected = False
                raise ADBCommunicationError("Device boot timeout exceeded")
            # collect android id from device
            # this also helps to ensure the device is functioning properly
            result = self.shell(
                ["settings", "get", "secure", "android_id"], device_required=False
            )
            if result.exit_code != 0:
                LOG.debug("failed to retrieve Android ID")
                self.connected = False
                raise ADBSessionError("Device in invalid state")
            self.device_id = result.output
            # get active user
            result = self.shell(["whoami"], device_required=False, timeout=30)
            if result.exit_code != 0 or not result.output:
                LOG.debug("failed to retrieve active user")
                raise ADBSessionError("Device in invalid state")
            self._root = result.output == "root"
            if as_root:
                # handle root login
                if not self._root:
                    if root_called:
                        LOG.debug("root login attempt failed")
                        raise ADBSessionError("Root login failed")
                    self.call(["root"], timeout=30)
                    retry = True
                    root_called = True
                    self.connected = False
                    continue
                # handle SELinux
                if self.get_enforce():
                    if set_enforce_called:
                        self.connected = False
                        raise ADBSessionError("set_enforce(0) failed!")
                    # set SELinux to run in permissive mode
                    self.set_enforce(0)
                    retry = True
                    set_enforce_called = True
                    self.connected = False
                    continue
        assert self.connected

    def devices(self, any_state: bool = True) -> dict[str, str]:
        """Devices visible to ADB.

        Args:
            any_state: Include devices in a state other than "device".

        Returns:
            A mapping of devices and their state.
        """
        result = self.call(["devices"], timeout=30)
        devices: dict[str, str] = {}
        if result.exit_code != 0:
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

    def disconnect(self, unroot: bool = True) -> None:
        """Disconnect.

        Args:
            unroot: Attempt to unroot device.

        Returns:
            None
        """
        if not self.connected:
            LOG.debug("already disconnected")
            return
        if self._root and unroot:
            # attempt to unroot (device may be unresponsive)
            with suppress(ADBCommandError, ADBCommunicationError):
                if self.call(["unroot"], timeout=10).exit_code == 0:
                    self._root = False
            if self._root:
                LOG.debug("'unroot' failed during disconnect")
        self.connected = False

    def get_enforce(self) -> bool:
        """Get SELinux state.

        Args:
            None

        Returns:
            True if "Enforcing" otherwise False.
        """
        status = self.shell(["getenforce"]).output
        if status == "Enforcing":
            return True
        if status != "Permissive":
            LOG.warning("Unexpected SELinux state '%s'", status)
        return False

    @classmethod
    def get_package_name(cls, apk: Path) -> str | None:
        """Retrieve the package name from an APK.

        Args:
            apk: APK to retrieve the package name from.

        Returns:
            Package name or None.
        """
        if not apk.is_file():
            raise FileNotFoundError("APK path must point to a file")
        aapt = cls._aapt_check()
        apk_info = check_output((aapt, "dump", "badging", str(apk)))
        for line in apk_info.splitlines():
            if line.startswith(b"package: name="):
                return line.split()[1][5:].strip(b"'").decode("utf-8", errors="ignore")
        return None

    def get_pid(self, package_name: str) -> int | None:
        """Retrieve process ID for the process with the specified package name.

        Args:
            package_name: Package name to use to find process PID.

        Returns:
            PID of the process with the specified package name if it exists or None.
        """
        result = self.shell(["pidof", package_name], timeout=30)
        return int(result.output) if result.exit_code == 0 else None

    def install(self, apk: Path) -> str:
        """Install APK on the connected device, grant R/W permissions to /sdcard and
        lookup the name of the installed APK.

        Args:
            apk: APK to install.

        Returns:
            Package name of APK that has been installed.
        """
        LOG.debug("installing %s", apk)
        if not apk.is_file():
            raise FileNotFoundError(f"APK does not exist '{apk}'")
        # lookup package name
        pkg_name = self.get_package_name(apk)
        if pkg_name is None:
            raise ADBSessionError("Could not find APK package name")
        if self.call(["install", "-g", "-r", str(apk)], timeout=180).exit_code != 0:
            raise ADBSessionError(f"Failed to install '{apk}'")
        # set permissions
        self.shell(
            ["pm", "grant", pkg_name, "android.permission.READ_EXTERNAL_STORAGE"]
        )
        self.shell(
            ["pm", "grant", pkg_name, "android.permission.WRITE_EXTERNAL_STORAGE"]
        )
        LOG.debug("installed package '%s' (%s)", pkg_name, apk)
        return pkg_name

    def install_file(
        self,
        src: Path,
        dst: PurePosixPath,
        mode: str | None = None,
        context: int | None = None,
    ) -> None:
        """Install file on the device filesystem and set permissions.

        Args:
            src: File to install on the device.
            dst: Location on device to install file.
            mode: chmod mode to use.
            context: chcon context to use.

        Returns:
            None
        """
        remote_dst = dst / src.name
        self.push(src, remote_dst)
        self.shell(["chown", "root.shell", str(remote_dst)])
        if mode is not None:
            self.shell(["chmod", mode, str(remote_dst)])
        if context is not None:
            self.shell(["chcon", str(context), str(remote_dst)])

    def is_installed(self, package_name: str) -> bool:
        """Check if a package is installed on the connected device.

        Args:
            package_name: Package name to look up on the device.

        Returns:
            True if the package is installed on the device otherwise False.
        """
        return package_name in self.packages

    def listdir(self, path: PurePosixPath) -> list[PurePosixPath]:
        """Contents of a directory.

        Args:
            path: Directory to list the contents of.

        Returns:
            Directory content listing.
        """
        result = self.shell(["ls", "-A", str(path)])
        if result.exit_code != 0:
            raise FileNotFoundError(f"'{path}' does not exist")
        return [PurePosixPath(x) for x in result.output.splitlines()]

    def open_files(
        self,
        pid: int | None = None,
        children: bool = False,
        files: Iterable[PurePosixPath] | None = None,
    ) -> Generator[tuple[int, PurePosixPath]]:
        """Look up open file on the device.

        Args:
            pid: Only include files where the process with the matching PID has an open
                 file handle.
            children: Include file opened by processes with a parent PID matching pid.
                      pid is required when children is set to True.
            files: Limit results to these specific files.

        Yields:
            PID and path of the open file.
        """
        LOG.debug("open_files(pid=%r, children=%s, files=%r", pid, children, files)
        cmd = ["lsof"]
        if pid is not None:
            pids = [str(pid)]
            if children:
                pids.extend(str(x.pid) for x in self._get_procs(pid_children=pid))
            cmd.extend(("-p", ",".join(pids)))
        else:
            assert not children, "children requires pid"
            pids = None
        if files:
            cmd.extend(str(x) for x in files)
        for line in self.shell(cmd).output.splitlines():
            if line.endswith("Permission denied)") or " REG " not in line:
                # only include regular files for now
                continue
            with suppress(ValueError):
                file_info = line.split()
                if pids is None or file_info[1] in pids:
                    # tuple containing pid and filename
                    yield (int(file_info[1]), PurePosixPath(file_info[-1]))

    @property
    def packages(self) -> Generator[str]:
        """Look up packages installed on the connected device.

        Args:
            None

        Yields:
            Names of the installed packages
        """
        result = self.shell(["pm", "list", "packages"])
        if result.exit_code == 0:
            for line in result.output.splitlines():
                if line.startswith("package:"):
                    yield line[8:]

    def process_exists(self, pid: int) -> bool:
        """Check if a process with a matching pid exists on the connected device.

        Args:
            pid: Process ID to lookup

        Returns:
            True if the process exists otherwise False
        """
        # this is called frequently and should be as light weight as possible
        str_pid = str(pid)
        return (
            str_pid in self.shell(["ps", "-p", str_pid, "-o", "pid"], timeout=30).output
        )

    def pull(self, src: PurePosixPath, dst: Path) -> bool:
        """Copy file from connected device.

        Args:
            src: File on the device to copy.
            dst: Location on the local machine to copy the file to.

        Returns:
            True if successful otherwise False
        """
        LOG.debug("pull('%s', '%s')", src, dst)
        return self.call(["pull", str(src), str(dst)], timeout=180).exit_code == 0

    def push(self, src: Path, dst: PurePosixPath) -> bool:
        """Copy file to connected device.

        Args:
            src: File on the local machine to copy.
            dst: Location on the connected device to copy the file to.

        Returns:
            True if successful otherwise False
        """
        LOG.debug("push('%s', '%s')", src, dst)
        if not src.exists():
            raise FileNotFoundError(f"'{src}' does not exist")
        return self.call(["push", str(src), str(dst)], timeout=180).exit_code == 0

    def realpath(self, path: PurePosixPath) -> PurePosixPath:
        """Get canonical path of the specified path.

        Args:
            path: File on the connected device.

        Returns:
            Canonical path of the specified path.
        """
        result = self.shell(["realpath", str(path)])
        if result.exit_code != 0:
            raise FileNotFoundError(f"'{path}' does not exist")
        return PurePosixPath(result.output)

    def reboot_device(self, boot_timeout: int = 300) -> None:
        """Reboot the connected device and reconnect.

        Args:
            boot_timeout: Seconds to wait for device boot to complete.

        Returns:
            None
        """
        was_root = self._root
        self.call(["reboot"])
        self.connected = False
        self.connect(as_root=was_root, boot_timeout=boot_timeout)
        # TODO: better error handling
        assert self.connected, "Device did not connect after reboot"

    def remount(self) -> None:
        """Remount system partition as writable.

        Args:
            None

        Returns:
            None
        """
        assert self._root
        result = self.call(["remount"])
        if (
            result.exit_code != 0
            or "Permission denied" in result.output
            or "remount failed" in result.output
        ):
            raise ADBSessionError("Remount failed, is '-writable-system' set?")

    def reverse(self, remote: int, local: int) -> bool:
        """

        Args:
            remote: Port to bind to on connected device.
            local: Port to bind to on local machine.

        Returns:
            True if successful otherwise False.
        """
        assert 1024 < local < 0x10000
        assert 1024 < remote < 0x10000
        cmd = ["reverse", f"tcp:{remote}", f"tcp:{local}"]
        return self.call(cmd, timeout=10).exit_code == 0

    def reverse_remove(self, remote: int | None = None) -> bool:
        """

        Args:
            remote: Port to unbind from on connected device.

        Returns:
            True if successful otherwise False.
        """
        cmd = ["reverse"]
        if remote is not None:
            assert 1024 < remote < 0x10000
            cmd.append("--remove")
            cmd.append(f"tcp:{remote}")
        else:
            cmd.append("--remove-all")
        return self.call(cmd, device_required=False, timeout=10).exit_code == 0

    def sanitizer_options(self, prefix: str, options: Mapping[str, str]) -> None:
        """Set sanitizer options.

        Args:
            prefix: Prefix to use when setting "<prefix>_OPTIONS".
            options: Option/values to set.

        Returns:
            None
        """
        prefix = prefix.lower()
        assert prefix == "asan", "only ASan is supported atm"
        self.shell(["rm", "-f", f"{prefix}.options.gecko"])
        # TODO: use common temp dir
        with TemporaryDirectory(prefix="sanopts_") as working_path:
            optfile = Path(working_path) / (f"{prefix}.options.gecko")
            optfile.write_text(":".join(f"{x[0]}={x[1]}" for x in options.items()))
            # TODO: use push() instead?
            self.install_file(optfile, DEVICE_TMP, mode="666")

    def set_enforce(self, value: int) -> None:
        """Set SELinux mode.

        Args:
            value: 1 to set 'Enforced' or 0 to set 'Permissive'

        Returns:
            None
        """
        assert value in (0, 1)
        if not self._root:
            LOG.warning("set_enforce requires root")
        self.shell(["setenforce", str(value)])

    def shell(
        self, cmd: Sequence[str], device_required: bool = True, timeout: int = 60
    ) -> ADBResult:
        """Execute an ADB shell command via a non-interactive shell.

        Args:
            cmd: Strings to pass as arguments when calling ADB.
            device_required: A device must be available.
            timeout: Seconds to wait for ADB call to complete.

        Returns:
            The exit code of the ADB call and stderr and stdout.
        """
        assert cmd
        return self.call(
            ("shell", "-T", "-n", *cmd),
            device_required=device_required,
            timeout=timeout,
        )

    def uninstall(self, package: str) -> bool:
        """Uninstall package from the connected device.

        Args:
            package: Name of package.

        Returns:
            True if successful otherwise False
        """
        if not self.connected:
            LOG.debug("already disconnected")
            return False
        return self.call(["uninstall", package], timeout=60).exit_code == 0

    def wait_for_boot(self, timeout: int, poll_wait: int = 1) -> bool:
        """Wait for device to boot.

        Args:
            timeout: Time in seconds to wait for device to boot.
            poll_wait: Time in seconds between checks.

        Returns:
            True if device has booted successfully otherwise False.
        """
        deadline = time() + timeout
        cmd = ("getprop", "sys.boot_completed")
        while True:
            if self.shell(cmd, device_required=False).output == "1":
                return True
            if time() >= deadline:
                break
            sleep(poll_wait)
        return False
