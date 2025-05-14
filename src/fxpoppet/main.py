# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from argparse import ArgumentParser, Namespace
from logging import DEBUG, ERROR, INFO, WARNING, basicConfig, getLogger
from os import getenv
from pathlib import Path

from .adb_process import ADBProcess
from .adb_session import DEVICE_TMP, ADBSession

LOG = getLogger("adb_device")

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


def configure_logging(log_level: int) -> None:
    """Configure log output level and formatting.

    Args:
        log_level: Set log level.

    Returns:
        None
    """
    # allow force enabling log_level via environment
    if getenv("DEBUG", "0").lower() in ("1", "true"):
        log_level = DEBUG
    if log_level == DEBUG:
        date_fmt = None
        log_fmt = "%(asctime)s %(levelname).1s %(name)s | %(message)s"
    else:
        date_fmt = "%Y-%m-%d %H:%M:%S"
        log_fmt = "[%(asctime)s] %(message)s"
    basicConfig(format=log_fmt, datefmt=date_fmt, level=log_level)


def parse_args(argv: list[str] | None = None) -> Namespace:
    """Argument parsing"""
    log_level_map = {"ERROR": ERROR, "WARN": WARNING, "INFO": INFO, "DEBUG": DEBUG}

    parser = ArgumentParser(description="ADB Device Wrapper")
    parser.add_argument(
        "--airplane-mode",
        choices=(0, 1),
        type=int,
        help="Enable(1) or disable(0) airplane mode",
    )
    parser.add_argument("--install", type=Path, help="APK to install")
    parser.add_argument("--launch", type=Path, help="APK to launch")
    parser.add_argument(
        "--log-level",
        choices=sorted(log_level_map),
        default="INFO",
        help="Configure console logging (default: %(default)s)",
    )
    parser.add_argument("--logs", type=Path, help="Location to save logs")
    parser.add_argument("--ip", help="IP address of target device")
    parser.add_argument(
        "--non-root", action="store_true", help="Connect as non-root user"
    )
    parser.add_argument(
        "--port", default=5555, type=int, help="ADB listening port on target device"
    )
    parser.add_argument(
        "--prep", type=Path, help="APK to use to prepare the device for fuzzing."
    )

    # sanity check args
    args = parser.parse_args(argv)
    if not any((args.airplane_mode is not None, args.install, args.launch, args.prep)):
        parser.error("No options selected")
    for apk in (args.install, args.launch, args.prep):
        if apk is not None and not apk.is_file():
            parser.error(f"Invalid APK '{apk}'")
    args.log_level = log_level_map[args.log_level]
    return args


def main(args: Namespace) -> int:
    """Main function"""
    configure_logging(args.log_level)
    LOG.info("Connecting to device...")
    session = ADBSession.create(args.ip, args.port, as_root=not args.non_root)
    if session is None:
        LOG.error("Failed to connect to IP: %s on port: %d", args.ip, args.port)
        return 1
    try:
        if args.prep is not None:
            LOG.info("Preparing device...")
            args.airplane_mode = 1
            args.install = args.prep
            # disable some UI animations
            session.shell(["settings", "put", "global", "animator_duration_scale", "0"])
            session.shell(
                ["settings", "put", "global", "transition_animation_scale", "0"]
            )
            session.shell(["settings", "put", "global", "window_animation_scale", "0"])
            # keep device awake
            session.shell(["svc", "power", "stayon", "true"])
        if args.airplane_mode is not None:
            LOG.debug("Setting airplane mode (%d)...", args.airplane_mode)
            session.airplane_mode = args.airplane_mode == 1
            LOG.info(
                "Airplane mode %s.", "enabled" if args.airplane_mode else "disabled"
            )
        if args.install is not None:
            pkg_name = ADBSession.get_package_name(args.install)
            if pkg_name is None:
                LOG.error("Failed to lookup package name in '%s'", args.install)
                return 1
            if session.uninstall(pkg_name):
                LOG.info("Uninstalled existing '%s'.", pkg_name)
            LOG.info("Installing '%s' from '%s'...", pkg_name, args.install)
            package = session.install(args.install)
            if not package:
                LOG.error("Could not install '%s'", args.install)
                return 1
            llvm_sym = args.install.parent / "llvm-symbolizer"
            if llvm_sym.is_file():
                LOG.info("Installing llvm-symbolizer...")
                session.install_file(llvm_sym, DEVICE_TMP, mode="777")
            # set wait for debugger
            # session.shell(["am", "set-debug-app", "-w", "--persistent", package])
            LOG.info("Installed %s.", package)
        if args.launch:
            pkg_name = ADBSession.get_package_name(args.launch)
            if pkg_name is None:
                LOG.error("Failed to lookup package name in '%s'", args.install)
                return 1
            session.symbols[pkg_name] = args.launch.parent / "symbols"
            proc = ADBProcess(pkg_name, session)
            try:
                proc.launch("about:blank", launch_timeout=360)
                assert proc.is_running(), "browser not running?!"
                LOG.info("Launched.")
                proc.wait()
            except KeyboardInterrupt:  # pragma: no cover
                LOG.info("Aborting...")
            finally:
                proc.close()
                if args.logs is not None:
                    proc.save_logs(args.logs)
                proc.cleanup()
                LOG.info("Closed.")
    finally:
        session.disconnect()
    return 0
