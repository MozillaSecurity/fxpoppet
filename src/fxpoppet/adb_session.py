# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
from logging import getLogger
from pathlib import Path, PurePosixPath
from shutil import which
from subprocess import check_output
from tempfile import TemporaryDirectory
from time import perf_counter
from typing import TYPE_CHECKING

from .adb_device import ADBDevice
from .adb_wrapper import ANDROID_SDK_ROOT

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable, Mapping

LOG = getLogger(__name__)

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


@dataclass(eq=False, frozen=True)
class DeviceProcessInfo:
    """Details of a process on the connected device."""

    memory: int
    name: str
    pid: int
    ppid: int


DEVICE_TMP = PurePosixPath("/data/local/tmp")


class ADBSessionError(Exception):
    """Operation failed unexpectedly or session state is invalid"""


class ADBSession:
    """Remote Android device session management.

    Attributes:
        device: ADBDevice to interact with.
        symbols: Location of symbols on the local machine.
    """

    __slots__ = ("device", "symbols")

    def __init__(self, device: ADBDevice) -> None:
        self.device: ADBDevice = device
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
        aapt_bin = next(ANDROID_SDK_ROOT.glob("android-*/aapt"), None)
        if aapt_bin:
            LOG.debug("using recommended aapt from '%s'", aapt_bin)
            return str(aapt_bin)
        installed_bin = which("aapt")
        if installed_bin is None:
            raise OSError("Please install AAPT")
        # TODO: update this to check aapt version
        LOG.warning("Using aapt binary from '%s'", installed_bin)
        return installed_bin

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
        results = self.device.shell(cmd)
        if results is not None:
            for line in results.output.splitlines()[1:]:
                with suppress(ValueError):
                    proc_id, ppid, memory, name = line.split()
                    yield DeviceProcessInfo(int(memory), name, int(proc_id), int(ppid))
                    continue
                LOG.debug("failed to parse ps line '%s'", line)

    @property
    def airplane_mode(self) -> bool:
        """Get the current state of airplane mode.

        Args:
            None

        Returns:
            True if airplane mode is enabled otherwise False.
        """
        result = self.device.shell(("settings", "get", "global", "airplane_mode_on"))
        return result is not None and result.output.startswith("1")

    @airplane_mode.setter
    def airplane_mode(self, state: bool) -> None:
        """Enable/disable airplane mode.

        Args:
            state: True will enable and False will disable airplane mode.

        Returns:
            None
        """
        self.device.shell(
            ("settings", "put", "global", "airplane_mode_on", ("1" if state else "0"))
        )
        self.device.shell(
            (
                "am",
                "broadcast",
                "-a",
                "android.intent.action.AIRPLANE_MODE",
            )
        )

    def clear_logs(self) -> bool:
        """Call 'adb logcat --clear' to wipe logs.

        Args:
            None

        Returns:
            True if logs were cleared otherwise False.
        """
        result = self.device.call(("logcat", "--clear"))
        return result is not None and result.exit_code == 0

    def collect_logs(self, pid: int | None = None) -> str | None:
        """Collect logs from device with logcat.

        Args:
            pid: Process ID to collect logs from. If pid is None Logs from all
                 processes will be collected.

        Returns:
            Logcat output if available otherwise None.
        """
        LOG.debug("collect_logs()")
        cmd = ["logcat", "-d", "*:I"]
        if pid is not None:
            cmd.append(f"--pid={pid}")
        result = self.device.call(cmd)
        return result.output if result and result.exit_code == 0 else None

    @classmethod
    def connect(
        cls, serial: str, as_root: bool = True, boot_timeout: int = 300
    ) -> ADBSession:
        """Connect and configure a device.

        Args:
            serial: Serial of Android device to use.
            as_root: Attempt to enable root. Default is True.
            boot_timeout: Seconds to wait for device boot to complete.

        Returns:
            ADBSession object.
        """
        assert boot_timeout > 0
        deadline = perf_counter() + boot_timeout
        device = ADBDevice.connect(serial, boot_timeout)
        remaining = max(deadline - perf_counter(), 1)
        if device is None or not device.wait_for_boot(remaining):
            raise ADBSessionError("Device boot timeout exceeded")
        if as_root:
            # handle root login
            device.call(("root",))
            result = device.shell(("whoami",), wait_for_device=True)
            if result is None or result.output != "root":
                raise ADBSessionError("Root login failed")
            # set SELinux to run in permissive mode
            device.shell(("setenforce", "0"))
            result = device.shell(("getenforce",), wait_for_device=True)
            if result is None or result.output != "Permissive":
                raise ADBSessionError("set_enforce(0) failed!")
        return cls(device)

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
        result = self.device.shell(("pidof", package_name))
        return int(result.output) if result and result.exit_code == 0 else None

    def install(self, apk: Path) -> str:
        """Install APK on the connected device, grant R/W permissions to /sdcard and
        lookup the name of the installed APK.

        Args:
            apk: APK to install.

        Returns:
            Package name of APK that has been installed.
        """
        LOG.debug("installing apk...")
        if not apk.is_file():
            raise FileNotFoundError(f"APK does not exist '{apk}'")
        # lookup package name
        pkg_name = self.get_package_name(apk)
        if pkg_name is None:
            raise ADBSessionError("Could not find APK package name")
        result = self.device.call(("install", "-g", "-r", str(apk)), timeout=180)
        if result is None or result.exit_code != 0:
            raise ADBSessionError(f"Failed to install '{apk}'")
        # set permissions
        self.device.shell(
            ("pm", "grant", pkg_name, "android.permission.READ_EXTERNAL_STORAGE")
        )
        self.device.shell(
            ("pm", "grant", pkg_name, "android.permission.WRITE_EXTERNAL_STORAGE")
        )
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
        if self.push(src, remote_dst):
            self.device.shell(("chown", "root.shell", str(remote_dst)))
            if mode is not None:
                self.device.shell(("chmod", mode, str(remote_dst)))
            if context is not None:
                self.device.shell(("chcon", str(context), str(remote_dst)))

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
        result = self.device.shell(("ls", "-A", str(path)))
        if result is None:
            return []
        if result.exit_code != 0:
            raise FileNotFoundError(f"'{path}' does not exist")
        return [PurePosixPath(x) for x in result.output.splitlines()]

    def open_files(
        self,
        pid: int | None = None,
        children: bool = False,
        files: Iterable[PurePosixPath] | None = None,
    ) -> Generator[tuple[int, PurePosixPath]]:
        """Look up open files on the device.

        Args:
            pid: Only include files where the process with the matching PID has an open
                 file handle. Required when `children` is set to True.
            children: Include file opened by processes with a parent PID matching pid.
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
        results = self.device.shell(cmd)
        if results is not None:
            for line in results.output.splitlines():
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
            Names of the installed packages.
        """
        result = self.device.shell(("pm", "list", "packages"))
        if result and result.exit_code == 0:
            for line in result.output.splitlines():
                if line.startswith("package:"):
                    yield line[8:]

    def process_exists(self, pid: int) -> bool:
        """Check if a process with a matching pid exists on the connected device.

        Args:
            pid: Process ID to lookup.

        Returns:
            True if the process exists otherwise False.
        """
        # this is called frequently and should be as light weight as possible
        str_pid = str(pid)
        result = self.device.shell(("ps", "-p", str_pid, "-o", "pid"))
        return result is not None and str_pid in result.output

    def pull(self, src: PurePosixPath, dst: Path) -> bool:
        """Copy file from connected device.

        Args:
            src: File on the device to copy.
            dst: Location on the local machine to copy the file to.

        Returns:
            True if successful otherwise False
        """
        LOG.debug("pull('%s', '%s')", src, dst)
        result = self.device.call(("pull", str(src), str(dst)), timeout=180)
        return result is not None and result.exit_code == 0

    def push(self, src: Path, dst: PurePosixPath) -> bool:
        """Copy file to connected device.

        Args:
            src: File on the local machine to copy.
            dst: Location on the connected device to copy the file to.

        Returns:
            True if successful otherwise False.
        """
        LOG.debug("push('%s', '%s')", src, dst)
        if not src.exists():
            raise FileNotFoundError(f"'{src}' does not exist")
        result = self.device.call(("push", str(src), str(dst)), timeout=180)
        return result is not None and result.exit_code == 0

    def realpath(self, path: PurePosixPath) -> PurePosixPath | None:
        """Get canonical path of the specified path.

        Args:
            path: File on the connected device.

        Returns:
            Canonical path of the specified path.
        """
        result = self.device.shell(("realpath", str(path)))
        if result is None:
            return None
        if result.exit_code != 0:
            raise FileNotFoundError(f"'{path}' does not exist")
        return PurePosixPath(result.output)

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
        result = self.device.call(("reverse", f"tcp:{remote}", f"tcp:{local}"))
        return result is not None and result.exit_code == 0

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
        result = self.device.call(cmd)
        return result is not None and result.exit_code == 0

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
        self.device.shell(("rm", "-f", f"{prefix}.options.gecko"))
        # TODO: use common temp dir
        with TemporaryDirectory(prefix="sanopts_") as working_path:
            optfile = Path(working_path) / (f"{prefix}.options.gecko")
            optfile.write_text(":".join(f"{x[0]}={x[1]}" for x in options.items()))
            # TODO: use push() instead?
            self.install_file(optfile, DEVICE_TMP, mode="666")

    def uninstall(self, package: str) -> bool:
        """Uninstall package from the connected device.

        Args:
            package: Name of package.

        Returns:
            True if successful otherwise False
        """
        result = self.device.call(("uninstall", package))
        return result is not None and result.exit_code == 0
