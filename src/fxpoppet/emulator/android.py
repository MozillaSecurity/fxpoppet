# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Launch an Android Emulator on a free port."""

from __future__ import annotations

from argparse import ArgumentParser
from contextlib import suppress
from logging import DEBUG, INFO, basicConfig, getLogger
from os import environ, getenv
from pathlib import Path
from platform import system
from shutil import copy, rmtree
from socket import AF_INET, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET, socket
from subprocess import DEVNULL, Popen, TimeoutExpired, check_output
from tempfile import TemporaryDirectory
from time import sleep
from urllib.parse import urlparse
from xml.etree.ElementTree import (
    Element,
    SubElement,
    fromstring,
    parse,
    register_namespace,
    tostring,
)

from fuzzfetch.download import download_url, get_url, iec
from fuzzfetch.extract import extract_zip

__author__ = "Jesse Schwartzentruber"

EXE_SUFFIX = ".exe" if system() == "Windows" else ""
REPO_URL = "https://dl.google.com/android/repository/repository2-1.xml"
IMAGES_URL = "https://dl.google.com/android/repository/sys-img/android/sys-img2-1.xml"
LOG = getLogger(__name__)
SYS_IMG = "android-35"
WORKING_DIR = Path.home() / "fxpoppet-emulator"


def init_logging(debug: bool = False) -> None:
    """Initialize logging format and level.

    Args:
        debug: Enable debug logging.

    Returns:
        None
    """
    if debug or getenv("DEBUG") == "1":
        date_fmt = None
        log_fmt = "%(asctime)s %(levelname).1s %(name)s | %(message)s"
        log_level = DEBUG
    else:
        date_fmt = "%Y-%m-%d %H:%M:%S"
        log_fmt = "[%(asctime)s] %(message)s"
        log_level = INFO
    basicConfig(format=log_fmt, datefmt=date_fmt, level=log_level)


class AndroidPaths:
    """Helper to lookup Android SDK paths"""

    def __init__(
        self,
        sdk_root: Path | None = None,
        prefs_root: Path | None = None,
        emulator_home: Path | None = None,
        avd_home: Path | None = None,
    ) -> None:
        """Initialize an AndroidPaths object.

        Args:
            sdk_root: default ANDROID_SDK_ROOT value
            prefs_root: default ANDROID_PREFS_ROOT value
            emulator_home: default ANDROID_EMULATOR_HOME value
            avd_home: default ANDROID_AVD_HOME value
        """
        self._sdk_root = sdk_root
        self._prefs_root = prefs_root
        self._emulator_home = emulator_home
        self._avd_home = avd_home

    @property
    def sdk_root(self) -> Path:
        """Look up ANDROID_SDK_ROOT

        Args:
            None

        Returns:
            value of ANDROID_SDK_ROOT
        """
        if self._sdk_root is None:
            env_var = getenv("ANDROID_HOME")
            if env_var is not None:
                android_home = Path(env_var)
                if android_home.is_dir():
                    self._sdk_root = android_home
                    return android_home
            env_var = getenv("ANDROID_SDK_ROOT")
            if env_var is not None:
                self._sdk_root = Path(env_var)
            elif system() == "Windows":
                env_var = getenv("LOCALAPPDATA")
                assert env_var is not None
                self._sdk_root = Path(env_var) / "Android" / "sdk"
            elif system() == "Darwin":
                self._sdk_root = Path.home() / "Library" / "Android" / "sdk"
            else:
                self._sdk_root = Path.home() / "Android" / "Sdk"
        return self._sdk_root

    @property
    def prefs_root(self) -> Path:
        """Look up ANDROID_PREFS_ROOT.

        Args:
            None

        Returns:
            value of ANDROID_PREFS_ROOT
        """
        if self._prefs_root is None:
            env_var = getenv("ANDROID_PREFS_ROOT")
            if env_var is not None:
                self._prefs_root = Path(env_var)
            else:
                env_var = getenv("ANDROID_SDK_HOME")
                self._prefs_root = Path.home() if env_var is None else Path(env_var)
        return self._prefs_root

    @property
    def emulator_home(self) -> Path:
        """Look up ANDROID_EMULATOR_HOME

        Args:
            None

        Returns:
            value of ANDROID_EMULATOR_HOME
        """
        if self._emulator_home is None:
            env_var = getenv("ANDROID_EMULATOR_HOME")
            self._emulator_home = (
                self.prefs_root / ".android" if env_var is None else Path(env_var)
            )
        return self._emulator_home

    @property
    def avd_home(self) -> Path:
        """Look up ANDROID_AVD_HOME

        Args:
            None

        Returns:
            value of ANDROID_AVD_HOME
        """
        if self._avd_home is None:
            env_var = getenv("ANDROID_AVD_HOME")
            self._avd_home = (
                self.emulator_home / "avd" if env_var is None else Path(env_var)
            )
        return self._avd_home


PATHS = AndroidPaths(avd_home=WORKING_DIR / "avd")


class AndroidSDKRepo:
    """Android SDK repository"""

    def __init__(self, url: str) -> None:
        """Create an AndroidSDKRepo object.

        Args:
            url: SDK repo URL.
        """
        parts = urlparse(url)
        self.url_base = f"{parts.scheme}://{parts.netloc}{parts.path.rsplit('/', 1)[0]}"
        xml_string = get_url(url).content
        LOG.info("Downloaded manifest: %s (%sB)", url, iec(len(xml_string)))
        self.root = fromstring(xml_string)
        if system() == "Linux":
            self.host = "linux"
        elif system() == "Windows":
            self.host = "windows"
        elif system() == "Darwin":
            self.host = "darwin"
        else:
            raise RuntimeError(f"Unknown platform: '{system()}'")

    @staticmethod
    def read_revision(element: Element) -> tuple[int, int, int]:
        """Look for revision in an SDK package element.

        Args:
            element: Package element to find revision for.

        Returns:
            Major, minor, micro
        """
        rev = element.find("revision")
        if rev is None:
            raise RuntimeError("Revision not found")
        value = rev.find("major")
        major = int(value.text) if value is not None and value.text is not None else 0
        value = rev.find("minor")
        minor = int(value.text) if value is not None and value.text is not None else 0
        value = rev.find("micro")
        micro = int(value.text) if value is not None and value.text is not None else 0
        return (major, minor, micro)

    def get_file(
        self, package_path: str, out_path: Path, extract_package_path: bool = True
    ) -> None:
        """Install an Android SDK package.

        Args:
            package_path: xref for package in SDK XML manifest.
            out_path: Local path to extract package to.
            extract_package_path: Extract under package name from `package_path`.

        Returns:
            None
        """
        for package in self.root.findall(
            f".//remotePackage[@path='{package_path}']/channelRef[@ref='channel-0']/.."
        ):
            url = package.find(
                f"./archives/archive/[host-os='{self.host}']/complete/url"
            )
            if url is not None:
                break
            # check for the same thing without host-os
            # can't do this purely in x-path
            archive = package.find("./archives/archive/complete/url/../..")
            if archive is not None and archive.find("./host-os") is None:
                url = archive.find("./complete/url")
                if url is not None:
                    break
        else:
            raise RuntimeError(f"Package {package_path} not found!")

        # figure out where to extract package to
        path_parts = package_path.split(";")
        intermediates = path_parts[:-1]
        manifest_path = Path(out_path, *path_parts) / "package.xml"
        if not extract_package_path:
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            # out_path doesn't change
        elif intermediates:
            out_path = Path(out_path, *intermediates)
            out_path.mkdir(parents=True, exist_ok=True)

        # check for an existing manifest
        if manifest_path.is_file():
            # compare the remote version with local
            remote_rev = self.read_revision(package)
            tree = parse(manifest_path)
            assert tree is not None
            rev_element = tree.find("localPackage")
            assert rev_element is not None
            local_rev = self.read_revision(rev_element)
            if remote_rev <= local_rev:
                fmt_rev = ".".join(
                    "" if ver is None else f"{ver:d}" for ver in local_rev
                ).strip(".")
                LOG.info(
                    "Installed %s revision %s is sufficiently new",
                    package_path,
                    fmt_rev,
                )
                return

        with TemporaryDirectory() as dl_dir:
            zip_tmp = Path(dl_dir) / "package.zip"
            download_url(f"{self.url_base}/{url.text}", zip_tmp)
            extract_zip(zip_tmp, str(out_path))

        # write manifest
        register_namespace(
            "common", "http://schemas.android.com/repository/android/common/01"
        )
        register_namespace(
            "generic", "http://schemas.android.com/repository/android/generic/01"
        )
        register_namespace(
            "sys-img", "http://schemas.android.com/sdk/android/repo/sys-img2/01"
        )
        register_namespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")
        manifest = Element(
            "{http://schemas.android.com/repository/android/common/01}repository"
        )
        license_ = package.find("uses-license")
        assert license_ is not None
        element = self.root.find(f"./license[@id='{license_.get('ref')}']")
        assert element is not None
        manifest.append(element)
        local_package = SubElement(manifest, "localPackage")
        local_package.set("path", package_path)
        local_package.set("obsolete", "false")
        for entry in ("type-details", "revision", "display-name"):
            element = package.find(entry)
            # this assertion was added maintain exact functionality and satisfy mypy
            assert element is not None
            local_package.append(element)
        local_package.append(license_)
        deps = package.find("dependencies")
        if deps is not None:
            local_package.append(deps)
        manifest_bytes = (
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            + tostring(manifest, encoding="UTF-8")
        )
        # etree doesn't support xmlns in attribute values, so insert them manually
        if b"xmlns:generic=" not in manifest_bytes and b'"generic:' in manifest_bytes:
            manifest_bytes = manifest_bytes.replace(
                b"<common:repository ",
                (
                    b"<common:repository xmlns:generic="
                    b'"http://schemas.android.com/repository/android/generic/01" '
                ),
            )
        if b"xmlns:sys-img=" not in manifest_bytes and b'"sys-img:' in manifest_bytes:
            manifest_bytes = manifest_bytes.replace(
                b"<common:repository ",
                (
                    b"<common:repository xmlns:sys-img="
                    b'"http://schemas.android.com/sdk/android/repo/sys-img2/01" '
                ),
            )
        manifest_path.write_bytes(manifest_bytes)


def _is_free(port: int) -> bool:
    sock = socket(AF_INET, SOCK_STREAM)
    try:
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        sock.settimeout(0.05)
        sock.bind(("localhost", port))
        sock.listen()
        return True
    except OSError:
        return False
    finally:
        sock.close()


class AndroidEmulatorError(Exception):
    """Indicate that an error occurred during Android emulator operation."""


class AndroidEmulator:
    """Proxy for Android emulator subprocess."""

    DESC = "Android emulator"

    def __init__(
        self,
        avd_name: str = "x86",
        port: int = 5554,
        snapshot: str = "never",
        env: dict[str, str] | None = None,
        headless: bool = False,
        target: str | None = None,
        verbose: bool = False,
        boot_timeout: int | None = 120,
    ) -> None:
        """Create an AndroidEmulator object.

        Args:
            avd_name: AVD machine definition name.
            port: ADB control port for emulator to use.
            snapshot: One of "never", "save", or "load". Determines snapshot
                      loading of emulator.
            env: Environment variables to pass to emulator subprocess.
            headless: Use -no-window to launch emulator.
            target: The target name (from builds.json).
            verbose: Enable verbose logging.
            boot_timeout: Time to wait for Android to boot in the emulator.
        """
        self.avd_name = avd_name
        self.emu = None
        self.env = dict(env or {})
        self.port = port
        self.snapshot = snapshot
        self.headless = headless
        self.target = target
        self.verbose = verbose

        assert self.snapshot in {"never", "save", "load"}

        avd_dir = PATHS.avd_home / f"{self.avd_name}.avd"

        args = []
        args.append("-writable-system")
        args.extend(("-selinux", "permissive"))

        if self.headless:
            args.append("-no-window")

        if self.verbose:
            args.append("-verbose")

        if self.snapshot == "never":
            args.append("-no-snapshot")

        elif self.snapshot == "save":
            args.append("-no-snapshot-load")

        elif self.snapshot == "load":
            args.append("-no-snapshot-save")

            # replace sdcard with firstboot version if exists
            sdcard = avd_dir / "sdcard.img"
            sdcard_fb = avd_dir / "sdcard.img.firstboot"
            if sdcard_fb.is_file():
                if sdcard.is_file():
                    sdcard.unlink()
                copy(sdcard_fb, sdcard)

        args.extend(("-port", f"{self.port:d}"))
        args.append(f"@{self.avd_name}")

        output = None if getLogger().getEffectiveLevel() == DEBUG else DEVNULL

        # make a copy before we modify the passed env dictionary
        env = dict(env or {})
        if system() == "Linux":
            if "DISPLAY" in environ:
                env["DISPLAY"] = getenv("DISPLAY", "")
            if "XAUTHORITY" in environ:
                env["XAUTHORITY"] = getenv("XAUTHORITY", "")
        env["ANDROID_AVD_HOME"] = str(PATHS.avd_home)

        LOG.info("Launching Android emulator with snapshot=%s", self.snapshot)
        emu = Popen(  # pylint: disable=consider-using-with
            [str(PATHS.sdk_root / "emulator" / f"emulator{EXE_SUFFIX}"), *args],
            env=env,
            stderr=output,
            stdout=output,
        )
        try:
            sleep(5)
        except Exception:
            if emu.poll() is None:
                emu.terminate()
            emu.wait()
            raise
        if emu.poll() is not None:
            raise AndroidEmulatorError("Failed to launch emulator")

        try:
            check_output(
                [
                    str(PATHS.sdk_root / "platform-tools" / f"adb{EXE_SUFFIX}"),
                    "wait-for-device",
                    "shell",
                    "while [[ -z $(getprop sys.boot_completed) ]];do sleep 1;done",
                ],
                timeout=boot_timeout,
                env={"ANDROID_SERIAL": f"emulator-{self.port:d}"},
            )
        except TimeoutExpired:
            emu.terminate()
            emu.wait()
            raise AndroidEmulatorError("Emulator failed to boot in time.") from None
        except:
            emu.terminate()
            emu.wait()
            raise

        self.emu = emu
        self.pid = emu.pid

    def relaunch(self) -> AndroidEmulator:
        """Create a new AndroidEmulator object created with the same parameters used to
        create this one.

        Args:
            None

        Return:
            AndroidEmulator: new AndroidEmulator instance.
        """
        return type(self)(
            avd_name=self.avd_name,
            port=self.port,
            snapshot=self.snapshot,
            env=self.env,
            headless=self.headless,
            target=self.target,
            verbose=self.verbose,
        )

    @staticmethod
    def install() -> None:
        """Ensure the emulator and system-image are installed.

        Args:
            None

        Returns:
            None
        """
        LOG.info("Checking Android SDK for updates...")

        PATHS.sdk_root.mkdir(parents=True, exist_ok=True)
        PATHS.avd_home.mkdir(parents=True, exist_ok=True)

        sdk_repo = AndroidSDKRepo(REPO_URL)
        img_repo = AndroidSDKRepo(IMAGES_URL)

        # get latest emulator for linux
        sdk_repo.get_file("emulator", PATHS.sdk_root)

        # get latest Google APIs system image
        img_repo.get_file(f"system-images;{SYS_IMG};default;x86_64", PATHS.sdk_root)

        # get latest platform-tools for linux
        sdk_repo.get_file("platform-tools", PATHS.sdk_root)

        # required for: aapt
        sdk_repo.get_file(
            "build-tools;28.0.3", PATHS.sdk_root, extract_package_path=False
        )

        # this is a hack and without it for some reason the following error can happen:
        # PANIC: Cannot find AVD system path. Please define ANDROID_SDK_ROOT
        (PATHS.sdk_root / "platforms").mkdir(exist_ok=True)

    def cleanup(self) -> None:
        """Cleanup any process files on disk.

        Args:
            None

        Returns:
            None
        """
        self.remove_avd(self.avd_name)

    def terminate(self) -> None:
        """Terminate the emulator process.

        Args:
            None

        Returns:
            None
        """
        assert self.emu is not None
        return self.emu.terminate()

    def poll(self) -> int | None:
        """Poll emulator process for exit status.

        Args:
            None

        Returns:
            Exit status of emulator process (None if still running).
        """
        assert self.emu is not None
        return self.emu.poll()

    def wait(self, timeout: int | None = None) -> int | None:
        """Wait for emulator process to exit.

        Args:
            timeout: If process does not exit within `timeout` seconds, raise
                     subprocess.TimeoutExpired.

        Returns:
            Exit status of emulator process (None if still running).
        """
        assert self.emu is not None
        result = self.emu.wait(timeout=timeout)

        if self.snapshot == "save":
            sleep(5)
            copy(
                PATHS.avd_home / f"{self.avd_name}.avd" / "sdcard.img",
                PATHS.avd_home / f"{self.avd_name}.avd" / "sdcard.img.firstboot",
            )

        return result

    def shutdown(self) -> None:
        """Use the emulator control channel to request clean shutdown.

        Args:
            None

        Returns:
            None
        """
        LOG.info("Initiating emulator shutdown")
        with suppress(ConnectionResetError), socket(AF_INET, SOCK_STREAM) as sock:
            sock.connect(("127.0.0.1", self.port))
            # read connection message
            lines = sock.recv(65536).splitlines()
            try:
                auth_token_idx = lines.index(
                    b"Android Console: you can find your <auth_token> in "
                )
            except ValueError:
                pass
            else:
                auth_token_path = lines[auth_token_idx + 1].strip(b"'")
                with open(auth_token_path, "rb") as auth_token_fp:
                    auth_token = auth_token_fp.read()
                sock.sendall(b"auth " + auth_token + b"\n")
                # receive auth message
                _ = sock.recv(65536)
            sock.sendall(b"kill\n")

    @staticmethod
    def search_free_ports(search_port: int | None = None) -> int:
        """Search for a pair of adjacent free ports for use by the Android Emulator.
        The emulator uses two ports: one as a QEMU control channel, and the other for
        ADB.

        Args:
            search_port: The first port to try. Ports are attempted sequentially
                         upwards. The default if None is given is 5554 (the usual ADB
                         port).

        Returns:
            The lower port of a pair of two unused ports.
        """
        port = search_port or 5554

        # start search for 2 free ports at search_port, and look upwards sequentially
        # from there
        while port + 1 <= 0xFFFF:
            for i in range(2):
                if not _is_free(port + i):
                    # continue searching at the next untested port
                    port = port + i + 1
                    break
            else:
                return port
        raise AndroidEmulatorError("no open range could be found")

    @staticmethod
    def remove_avd(avd_name: str) -> None:
        """Remove an Android emulator machine definition (AVD). No error is raised if
        the AVD doesn't exist.

        Args:
            avd_name: Name of AVD to remove.

        Returns:
            None
        """
        avd_ini = PATHS.avd_home / f"{avd_name}.ini"
        if avd_ini.is_file():
            avd_ini.unlink()
        avd_dir = PATHS.avd_home / f"{avd_name}.avd"
        if avd_dir.is_dir():
            rmtree(avd_dir)

    @classmethod
    def create_avd(cls, avd_name: str, sdcard_size: int = 500) -> None:
        """Create an Android emulator machine definition (AVD).

        Args:
            avd_name: Name of AVD to create.
            sdcard_size: Size of SD card image to use, in megabytes.

        Returns:
            None
        """
        mksd_path = PATHS.sdk_root / "emulator" / f"mksdcard{EXE_SUFFIX}"
        assert mksd_path.is_file(), f"Missing {mksd_path}"
        LOG.info("Creating AVD '%s'", avd_name)

        # create an avd
        PATHS.avd_home.mkdir(exist_ok=True)
        api_gapi = PATHS.sdk_root / "system-images" / SYS_IMG / "default"
        cls.remove_avd(avd_name)
        avd_ini = PATHS.avd_home / f"{avd_name}.ini"
        avd_dir = PATHS.avd_home / f"{avd_name}.avd"
        avd_dir.mkdir()

        with avd_ini.open("w") as ini:
            print("avd.ini.encoding=UTF-8", file=ini)
            print(f"path={avd_dir}", file=ini)
            print(f"path.rel=avd/{avd_name}.avd", file=ini)
            print("target={SYS_IMG}", file=ini)

        avd_cfg = avd_dir / "config.ini"
        assert not avd_cfg.is_file(), f"File exists '{avd_cfg}'"
        with avd_cfg.open("w") as cfg:
            print(f"AvdId={avd_name}", file=cfg)
            print("PlayStore.enabled=false", file=cfg)
            print("abi.type=x86_64", file=cfg)
            print(f"avd.ini.displayname={avd_name}", file=cfg)
            print("avd.ini.encoding=UTF-8", file=cfg)
            print("disk.dataPartition.size=5000M", file=cfg)
            print("fastboot.forceColdBoot=no", file=cfg)
            print("hw.accelerometer=yes", file=cfg)
            print("hw.arc=false", file=cfg)
            print("hw.audioInput=yes", file=cfg)
            print("hw.battery=yes", file=cfg)
            print("hw.camera.back=emulated", file=cfg)
            print("hw.camera.front=emulated", file=cfg)
            print("hw.cpu.arch=x86_64", file=cfg)
            print("hw.cpu.ncore=4", file=cfg)
            print("hw.dPad=no", file=cfg)
            print("hw.device.hash2=MD5:524882cfa9f421413193056700a29392", file=cfg)
            print("hw.device.manufacturer=Google", file=cfg)
            print("hw.device.name=pixel", file=cfg)
            print("hw.gps=yes", file=cfg)
            print("hw.gpu.enabled=yes", file=cfg)
            print("hw.gpu.mode=auto", file=cfg)
            print("hw.initialOrientation=Portrait", file=cfg)
            print("hw.keyboard=yes", file=cfg)
            print("hw.lcd.density=480", file=cfg)
            print("hw.lcd.height=1920", file=cfg)
            print("hw.lcd.width=1080", file=cfg)
            print("hw.mainKeys=no", file=cfg)
            print("hw.ramSize=6144", file=cfg)
            print("hw.sdCard=yes", file=cfg)
            print("hw.sensors.orientation=yes", file=cfg)
            print("hw.sensors.proximity=yes", file=cfg)
            print("hw.trackBall=no", file=cfg)
            print(f"image.sysdir.1=system-images/{SYS_IMG}/default/x86_64/", file=cfg)
            print("runtime.network.latency=none", file=cfg)
            print("runtime.network.speed=full", file=cfg)
            print(f"sdcard.size={sdcard_size:d}M", file=cfg)
            print("showDeviceFrame=no", file=cfg)
            print("skin.dynamic=yes", file=cfg)
            print("skin.name=1080x1920", file=cfg)
            print("skin.path=_no_skin", file=cfg)
            print("skin.path.backup=_no_skin", file=cfg)
            print("tag.display=Google APIs", file=cfg)
            print("tag.id=google_apis", file=cfg)
            print("vm.heapSize=256", file=cfg)

        if (api_gapi / "x86_64" / "userdata.img").exists():
            copy(api_gapi / "x86_64" / "userdata.img", avd_dir)

        sdcard = avd_dir / "sdcard.img"
        check_output([str(mksd_path), f"{sdcard_size:d}M", str(sdcard)])
        copy(sdcard, f"{sdcard}.firstboot")


def main(argv: list[str] | None = None) -> None:
    """Create and run an AVD and delete it when shutdown.

    Args:
        argv (list/None): Override sys.argv (for testing).

    Returns:
        None
    """
    aparser = ArgumentParser(prog="python -m bearspray.android")
    aparser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )
    aparser.add_argument(
        "--boot-timeout",
        "-t",
        default=60,
        type=float,
        help=(
            "Time to wait for Android to boot before retrying emulator launch "
            "(default: %(default)ss)"
        ),
    )
    aparser.add_argument(
        "--headless", action="store_true", help="Run emulator in headless mode"
    )
    aparser.add_argument(
        "--skip-dl",
        "-s",
        action="store_true",
        help="Skip download/update the Android SDK and system image",
    )
    args = aparser.parse_args(argv)

    if args.boot_timeout < 0:
        aparser.error("--boot-timeout must be positive")
    if args.boot_timeout == 0:
        args.boot_timeout = None

    init_logging(debug=args.verbose)

    if not args.skip_dl:
        AndroidEmulator.install()

    # Find a free port
    port = AndroidEmulator.search_free_ports()
    avd_name = f"x86.{port:d}"

    # Create an AVD and boot it once
    AndroidEmulator.create_avd(avd_name)
    try:
        # Boot the AVD
        emu = AndroidEmulator(
            port=port,
            avd_name=avd_name,
            verbose=args.verbose,
            boot_timeout=args.boot_timeout,
            headless=args.headless,
        )
        LOG.info("Android emulator is running on port %d", port)
        try:
            emu.wait()
        except KeyboardInterrupt:
            LOG.info("Aborting...")
        finally:
            if emu.poll() is None:
                emu.shutdown()
            # this should never timeout
            emu.wait(timeout=120)
    finally:
        AndroidEmulator.remove_avd(avd_name)


if __name__ == "__main__":
    main()
