# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import annotations

import re
from enum import Enum, auto
from logging import getLogger
from os import getenv
from pathlib import Path, PurePosixPath
from random import getrandbits
from shutil import copy, rmtree
from tempfile import TemporaryDirectory, mkdtemp
from time import sleep, time
from typing import TYPE_CHECKING

from ffpuppet.bootstrapper import Bootstrapper
from ffpuppet.minidump_parser import MinidumpParser
from yaml import safe_dump

from .adb_session import DEVICE_TMP, ADBSession, ADBSessionError

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable, Mapping

LOG = getLogger("adb_process")

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class Reason(Enum):
    """Indicates why the browser process was terminated"""

    # target crashed, aborted, triggered an assertion failure, etc...
    ALERT = auto()
    # target was closed by call to ADBProcess.close() or has not been launched
    CLOSED = auto()
    # target exited
    EXITED = auto()


class ADBLaunchError(ADBSessionError):
    """Browser launch related error."""


class ADBProcess:
    """ADB Process management.

    Attributes:
        _launches: Number of successful browser launches.
        _package: Package used as target process.
        _pid: Process ID of current target process.
        _profile_template: Profile used as a template.
        _session: Current ADB session.
        _working_path: Working directory on the connected device.
        logs: Location of logs on the local machine.
        profile: Location of profile on the connected device.
        reason: Indicates why the browser process was terminated.
    """

    # TODO:
    #  def clone_log(self, log_id, offset=0):
    #  def log_data(self, log_id, offset=0):
    #  def log_length(self, log_id):... likely not going to happen because of overhead

    __slots__ = (
        "_launches",
        "_package",
        "_pid",
        "_profile_template",
        # "_sanitizer_logs",
        "_session",
        "_working_path",
        "logs",
        "profile",
        "reason",
    )

    def __init__(
        self, package_name: str, session: ADBSession, use_profile: str | None = None
    ) -> None:
        assert package_name
        if not session.is_installed(package_name):
            raise ADBSessionError(f"Package '{package_name}' is not installed")
        self._launches = 0
        self._package = package_name
        self._pid: int | None = None
        self._profile_template = use_profile
        self._session = session
        # Note: geckview_example fails to read a profile from /sdcard/ atm
        self._working_path = DEVICE_TMP / f"ADBProc_{getrandbits(32):08X}"
        # self._sanitizer_logs = "%s/sanitizer_logs" % (self._working_path,)
        self.logs: Path | None = None
        self.profile: PurePosixPath | None = None
        self.reason: Reason | None = Reason.CLOSED

    def __enter__(self) -> ADBProcess:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        """Close running browser instance and remove any related files.

        Args:
            None

        Returns:
            None
        """
        if self._launches < 0:
            LOG.debug("clean_up() call ignored")
            return
        if self.reason is None:
            self.close()
        self._remove_logs()
        # negative 'self._launches' indicates clean_up() has been called
        self._launches = -1

    def clone_log(self) -> str:
        """Create a copy of existing logs.

        Args:
            None

        Returns:
            Log data.
        """
        # TODO: dump logs for all browser processes
        return self._session.collect_logs(pid=self._pid)

    def close(self) -> None:
        """Close running browser instance.

        Args:
            None

        Returns:
            None
        """
        assert self._launches > -1, "clean_up() has been called"
        if self.reason is not None:
            LOG.debug("already closed!")
            return
        try:
            crash_reports = tuple(self.find_crashreports())
            # set reason code
            if crash_reports:
                self.reason = Reason.ALERT
                self.wait_on_files(crash_reports)
            elif self.is_running():
                self.reason = Reason.CLOSED
            else:
                self.reason = Reason.EXITED
            self._terminate()
            self.wait()
            self._process_logs(crash_reports)
            # remove remote working path
            self._session.shell(["rm", "-rf", str(self._working_path)])
            # remove remote config yaml
            cfg_file = str(DEVICE_TMP / f"{self._package}-geckoview-config.yaml")
            self._session.shell(["rm", "-rf", cfg_file])
            # TODO: this should be temporary until ASAN_OPTIONS=log_file is working
            if self.logs and (self.logs / "log_asan.txt").is_file():
                self.reason = Reason.ALERT
        except ADBSessionError:
            LOG.warning("No device detected while closing process")
        self._pid = None
        self.profile = None
        if self.reason is None:
            self.reason = Reason.CLOSED

    def find_crashreports(self) -> Generator[PurePosixPath]:
        """Scan for crash reports.

        Args:
            None

        Yields:
            Crash reports found on the remote device.
        """
        # look for logs from sanitizers
        # for fname in self._session.listdir(self._sanitizer_logs):
        #    reports.append(os.path.join(self._sanitizer_logs, fname))

        if self.profile:
            keep_suffix = frozenset((".dmp", ".extra"))
            # check for minidumps
            md_path = self.profile / "minidumps"
            try:
                for fname in self._session.listdir(md_path):
                    if fname.suffix in keep_suffix:
                        yield md_path / fname
            except FileNotFoundError:
                LOG.debug("%s does not exist", md_path)

    def is_healthy(self) -> bool:
        """Verify the browser is in a good state by performing a series of checks.

        Args:
            None

        Returns:
            True if the browser is running and determined to be in a valid functioning
            state otherwise False.
        """
        if not self.is_running():
            return False
        return not any(self.find_crashreports())

    def is_running(self) -> bool:
        """Check if the browser is running.

        Args:
            None

        Returns:
            True if the browser is running otherwise False.
        """
        if self._pid is None or self.reason is not None:
            return False
        return self._session.process_exists(self._pid)

    def launch(
        self,
        url: str,
        env_mod: Mapping[str, str] | None = None,
        launch_timeout: int = 60,
        prefs_js: Path | None = None,
    ) -> bool:
        """Launch a new browser process.

        Args:
            url: URL to navigate to after launching the browser.
            env_mod: Environment modifier. Add, remove and update entries
                     in the prepared environment. Add and update by
                     setting value (str) and remove by setting entry value to None.
            launch_timeout: Timeout in seconds for launching the browser.
            prefs_js: prefs.js file to install in the Firefox profile.

        Returns:
            True if the browser was successfully launched otherwise False.
        """
        LOG.debug("launching - url: %s", url)
        assert self._launches > -1, "clean_up() has been called"
        assert self._pid is None, "Process is already running"
        assert self.reason is not None, "Process is already running"

        self._session.clear_logs()
        self._remove_logs()
        self.reason = None

        if ".fenix" in self._package:
            app = f"{self._package}/org.mozilla.fenix.IntentReceiverActivity"
        elif ".geckoview_example" in self._package:
            app = f"{self._package}/org.mozilla.geckoview_example.GeckoViewActivity"
        else:
            raise ADBLaunchError(f"Unsupported package '{self._package}'")

        # check app is not previously running
        if self._session.get_pid(self._package) is not None:
            raise ADBLaunchError(f"'{self._package}' is already running")

        # load prefs from prefs.js
        prefs = self.prefs_to_dict(prefs_js) if prefs_js else {}
        if prefs is None:
            raise ADBLaunchError(f"Invalid prefs.js file ({prefs_js})")

        # setup bootstrapper and reverse port
        # reverse does fail occasionally so use a retry loop
        for _ in range(10):
            bootstrapper = Bootstrapper.create()
            if not self._session.reverse(bootstrapper.port, bootstrapper.port):
                bootstrapper.close()
                LOG.debug("failed to reverse port, retrying...")
                sleep(0.25)
                continue
            break
        else:
            raise ADBLaunchError("Could not reverse port")
        try:
            # add additional prefs
            prefs.update(
                {
                    "capability.policy.localfilelinks.checkloaduri.enabled": (
                        "allAccess"
                    ),
                    "capability.policy.localfilelinks.sites": bootstrapper.location,
                    "capability.policy.policynames": "localfilelinks",
                    "network.proxy.allow_bypass": False,
                    "network.proxy.failover_direct": False,
                    "privacy.partition.network_state": False,
                }
            )
            # create location to store sanitizer logs
            # self._session.shell(["mkdir", "-p", self._sanitizer_logs])
            # create empty profile
            self.profile = self._working_path / f"gv_profile_{getrandbits(32):08X}"
            self._session.shell(["mkdir", "-p", str(self.profile)])
            # add environment variables
            env_mod = dict(env_mod or {})
            env_mod.setdefault("MOZ_SKIA_DISABLE_ASSERTS", "1")
            self._session.sanitizer_options(
                "asan",
                {
                    "abort_on_error": "1",
                    "color": "0",
                    "external_symbolizer_path": f"'{DEVICE_TMP / 'llvm-symbolizer'}'",
                    # "log_path": "'%s/log_san.txt'" % (self._sanitizer_logs,),
                    "symbolize": "1",
                },
            )

            # build *-geckoview-config.yaml
            # https://firefox-source-docs.mozilla.org/mobile/android/geckoview/...
            # consumer/automation.html#configuration-file-format
            with TemporaryDirectory(prefix="fxp_cfp_") as tmp_cfp:
                cfg_yml = Path(tmp_cfp) / f"{self._package}-geckoview-config.yaml"
                cfg_yml.write_text(
                    safe_dump(
                        {
                            "args": ["--profile", str(self.profile)],
                            "env": env_mod,
                            "prefs": prefs,
                        }
                    )
                )
                if not self._session.push(cfg_yml, DEVICE_TMP / cfg_yml.name):
                    raise ADBLaunchError(f"Could not upload '{cfg_yml.name}'")
            cmd = [
                "am",
                "start",
                "-W",
                "-n",
                app,
                "-a",
                "android.intent.action.VIEW",
                "-d",
                bootstrapper.location,
            ]
            if (
                "Status: ok"
                not in self._session.shell(cmd, timeout=launch_timeout).output
            ):
                raise ADBLaunchError(f"Could not launch '{self._package}'")
            self._pid = self._session.get_pid(self._package)
            bootstrapper.wait(self.is_healthy, url=url)
        finally:
            self._session.reverse_remove(bootstrapper.port)
            bootstrapper.close()
        self._launches += 1

        return self._pid is not None

    @property
    def launches(self) -> int:
        """Get the number of successful launches.

        Args:
            None

        Return:
            Number of successful launches.
        """
        assert self._launches > -1, "clean_up() has been called"
        return self._launches

    @staticmethod
    def prefs_to_dict(src: Path) -> dict[str, bool | int | str] | None:
        """Convert a prefs.js file to a dictionary.

        Args:
            None

        Return:
            Loaded pref values or None if the file cannot be processed.
        """
        pattern = re.compile(r"user_pref\((?P<name>.*?),\s*(?P<value>.*?)\);")
        out: dict[str, bool | int | str] = {}
        with src.open(encoding="utf-8") as in_fp:
            for line in in_fp:
                pref = pattern.match(line)
                if not pref:
                    continue
                # parse name
                name: str = pref.group("name")
                if not name:
                    LOG.error("Pref name is missing")
                    return None
                if name[0] == "'" == name[-1]:
                    name = name.strip("'")
                elif name[0] == '"' == name[-1]:
                    name = name.strip('"')
                else:
                    LOG.error("Pref name is not quoted (%s)", name)
                    return None
                if not name:
                    LOG.error("Pref name is empty")
                    return None
                # parse value
                value: str = pref.group("value")
                if not value:
                    LOG.error("Pref '%s' is missing value", name)
                    return None
                if value in ("false", "true"):
                    out[name] = value == "true"
                elif value[0] == "'" == value[-1]:
                    out[name] = value.strip("'")
                elif value[0] == '"' == value[-1]:
                    out[name] = value.strip('"')
                else:
                    try:
                        out[name] = int(value)
                    except ValueError:
                        LOG.error("Pref '%s' has invalid value '%s'", name, value)
                        return None
        return out

    def _process_logs(self, crash_reports: Iterable[PurePosixPath]) -> None:
        """Collect and process logs. This includes processing minidumps.

        Args:
            crash_reports: Files to collect and process.

        Return:
            None
        """
        assert self.logs is None
        if self.profile is None:
            LOG.debug("no logs to process since browser was not launched")
            return
        # TODO: use a common tmp dir
        self.logs = Path(mkdtemp(prefix="mp-logs_"))

        with (self.logs / "log_logcat.txt").open("w") as log_fp:
            # TODO: should this filter by pid or not?
            log_fp.write(self._session.collect_logs())
            # log_fp.write(self._session.collect_logs(pid=self._pid))
        self._split_logcat(self.logs, self._package)
        if not crash_reports:
            return

        # copy crash logs from the device
        unprocessed = self.logs / "unprocessed"
        unprocessed.mkdir()
        for fname in crash_reports:
            self._session.pull(fname, unprocessed)

        dmp_files = MinidumpParser.dmp_files(unprocessed)
        if dmp_files:
            if getenv("SAVE_DMP") == "1":
                for entry in unprocessed.iterdir():
                    if entry.suffix.lower() in (".dmp", ".extra"):
                        copy(entry, self.logs)
            if not MinidumpParser.mdsw_available():
                LOG.error("Unable to process minidump, minidump-stackwalk is required.")
                return
            # process minidump files and save output
            with MinidumpParser(
                symbols=self._session.symbols.get(self._package)
            ) as md_parser:
                for count, dmp_file in enumerate(dmp_files):
                    copy(
                        md_parser.create_log(dmp_file, f"log_minidump_{count:02d}.txt"),
                        self.logs,
                    )

    def _remove_logs(self) -> None:
        """Remove collected logs.

        Args:
            None

        Return:
            None
        """
        if self.logs is not None and self.logs.is_dir():
            rmtree(self.logs)
            self.logs = None

    @staticmethod
    def _split_logcat(logs: Path, package_name: str) -> None:
        # Roughly split out stderr and stdout from logcat
        # This is to support FuzzManager. The original logcat output is also
        # included in the report so nothing is lost.
        assert package_name
        logcat = logs / "log_logcat.txt"
        if not logcat.is_file():
            LOG.warning("log_logcat.txt does not exist!")
            return
        err_log = logs / "log_stderr.txt"
        if err_log.is_file():
            LOG.warning("log_stderr.txt already exist! Overwriting...")
        out_log = logs / "log_stdout.txt"
        if out_log.is_file():
            LOG.warning("log_stdout.txt already exist! Overwriting...")
        package_name_bytes = package_name.encode("utf-8")
        # create set of filter pids
        # this will include any line that mentions "Gecko", "MOZ_" or the package name
        asan_tid = None
        filter_pids = set()
        re_id = re.compile(rb"^\d+-\d+\s+(\d+[:.]){3}\d+\s+(?P<pid>\d+)\s+(?P<tid>\d+)")
        with logcat.open("rb") as lc_fp:
            for line in lc_fp:
                if (
                    b"Gecko" not in line
                    and b"MOZ_" not in line
                    and package_name_bytes not in line
                    and b"wrap.sh" not in line
                ):
                    continue
                m_id = re_id.match(line)
                if m_id is None:
                    continue
                filter_pids.add(m_id.group("pid"))
                if asan_tid is None and b": AddressSanitizer:" in line:
                    asan_tid = m_id.group("tid")
        LOG.debug("%d interesting pid(s) found in logcat output", len(filter_pids))
        # filter logs
        with (
            logcat.open("rb") as lc_fp,
            err_log.open("wb") as e_fp,
            out_log.open("wb") as o_fp,
        ):
            for line in lc_fp:
                # quick check if pid is in the line
                if not any(pid in line for pid in filter_pids):
                    continue
                # verify the line pid is in set of filter pids
                m_id = re_id.match(line)
                if m_id is None:
                    continue
                line_pid = m_id.group("pid")
                if not any(pid == line_pid for pid in filter_pids):
                    continue
                # strip logger info ... "07-27 12:10:15.442  9990  4234 E "
                line = re.sub(rb".+?\s[ADEIVW]\s+", b"", line)
                if line.startswith(b"GeckoDump"):
                    o_fp.write(line.split(b": ", 1)[-1])
                else:
                    e_fp.write(line.split(b": ", 1)[-1])
        # Break out ASan logs (to be removed when ASAN_OPTIONS=logs works)
        # This could be merged into the above block but it is kept separate
        # so it can be removed easily in the future.
        if asan_tid is not None:
            asan_log = logs / "log_asan.txt"
            if asan_log.is_file():
                LOG.warning("log_asan.txt already exist! Overwriting...")
            found_log = False
            with logcat.open("rb") as lc_fp, asan_log.open("wb") as o_fp:
                for line in lc_fp:
                    # quick check if thread id is in the line
                    if asan_tid not in line:
                        continue
                    # verify the line tid matches ASan thread id
                    m_id = re_id.match(line)
                    if m_id is None or m_id.group("tid") != asan_tid:
                        continue
                    # filter noise before the crash
                    if not found_log:
                        if b": AddressSanitizer:" not in line:
                            continue
                        found_log = True
                    # strip logger info ... "07-27 12:10:15.442  9990  4234 E "
                    line = re.sub(rb".+?\s[ADEIVW]\s+", b"", line)
                    o_fp.write(line.split(b": ", 1)[-1])

    def save_logs(self, dst: Path) -> None:
        """Save logs to specified location.

        Args:
            dst: Location to save logs to.

        Return:
            None
        """
        assert self.reason is not None, "Call close() first!"
        assert self._launches > -1, "clean_up() has been called"
        if self.logs is None:
            LOG.warning("No logs available to save.")
            return
        # copy logs to location specified by log_file
        dst.mkdir(parents=True, exist_ok=True)
        for entry in self.logs.iterdir():
            # skip directories
            if entry.is_file():
                copy(entry, dst)

    def wait_on_files(
        self,
        wait_files: Iterable[PurePosixPath],
        poll_rate: float = 0.5,
        timeout: int = 60,
    ) -> bool:
        """Wait for specified files to no longer be in use or the time limit to be hit
        before continuing.

        Args:
            wait_files: Files to wait on.
            poll_rate: Delay between checks.
            timeout: Number of seconds to wait.

        Return:
            True if all files are closed before the time limit otherwise False.
        """
        assert poll_rate >= 0
        assert timeout >= 0
        assert poll_rate <= timeout
        wait_end = time() + timeout
        files = frozenset(str(self._session.realpath(x)) for x in wait_files)

        while files:
            open_files = frozenset(str(x) for _, x in self._session.open_files())
            # check if any open files are in the wait file list
            if not files.intersection(open_files):
                break
            if wait_end <= time():
                LOG.debug(
                    "Timeout waiting for: %s", ", ".join(files.intersection(open_files))
                )
                return False
            sleep(poll_rate)
        return True

    def _terminate(self) -> None:
        """Force close the browser.

        Args:
            None

        Return:
            None
        """
        # TODO: is this the best way???
        self._session.shell(["am", "force-stop", self._package])

    def wait(self) -> None:
        """Wait for browser process.

        Args:
            None

        Return:
            None
        """
        while self.is_running():
            sleep(0.25)
