# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

from pytest import raises

from .adb_device import ADBDevice
from .adb_session import DEVICE_TMP, ADBSession, ADBSessionError
from .adb_wrapper import ADBResult, ADBWrapper


def test_adb_session_connect(mocker):
    """test ADBSession.connect()"""
    device_cls = mocker.patch("fxpoppet.adb_session.ADBDevice")
    # successful connection
    session = ADBSession.connect("fake-serial", as_root=False)
    assert session
    assert device_cls.connect.call_args.args == ("fake-serial", 300)
    assert session.device.wait_for_boot.call_count == 1
    # no device detected
    device_cls.connect.return_value = None
    with raises(ADBSessionError, match="Device boot timeout exceeded"):
        ADBSession.connect("fake-serial", as_root=False)
    # successful root connection
    device_cls.reset_mock(return_value=True)
    device_cls.connect.return_value.shell.side_effect = (
        # whoami
        ADBResult(0, "root"),
        # setenforce
        ADBResult(0, ""),
        # getenforce
        ADBResult(0, "Permissive"),
    )
    ADBSession.connect("fake-serial", as_root=True)
    assert device_cls.connect.return_value.shell.call_count == 3
    # failed root login
    device_cls.reset_mock(side_effect=True)
    device_cls.connect.return_value.shell.side_effect = (
        # whoami
        ADBResult(0, "user"),
    )
    with raises(ADBSessionError, match="Root login failed"):
        ADBSession.connect("fake-serial", as_root=True)
    # failed set enforce
    device_cls.reset_mock(side_effect=True)
    device_cls.connect.return_value.shell.side_effect = (
        # whoami
        ADBResult(0, "root"),
        # setenforce
        ADBResult(0, ""),
        # getenforce
        ADBResult(0, "Enforcing"),
    )
    with raises(ADBSessionError, match=r"set_enforce\(0\) failed!"):
        ADBSession.connect("fake-serial", as_root=True)


def test_adb_session_install(tmp_path, mocker):
    """test ADBSession.install()"""

    def fake_get_package_name(*_):
        with (
            ZipFile(apk_file, mode="r") as zfp,
            zfp.open("package-name.txt", "r") as pfp,
        ):
            return pfp.read().strip().decode("utf-8", errors="ignore")

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "install":
            assert cmd[1] == "-g"
            assert cmd[2] == "-r"
            if "test.apk" in cmd[3]:
                return ADBResult(0, "Success")
            return ADBResult(1, "")
        if cmd[0] == "shell":
            # strip "shell -n -T"
            shell_cmd = cmd[3:]
            assert shell_cmd[0] == "pm"
            assert shell_cmd[1] == "grant"
            assert shell_cmd[2] == "test-package.blah.foo"
            return ADBResult(0, "")
        raise AssertionError(f"unexpected command {cmd!r}")

    mocker.patch(
        "fxpoppet.adb_session.ADBSession.get_package_name",
        fake_get_package_name,
    )
    device = mocker.Mock(spec_set=ADBDevice)
    device.call.side_effect = fake_call
    session = ADBSession(device)
    # missing apk
    with raises(FileNotFoundError):
        session.install(Path("missing"))
    # bad apk
    pkg_file = tmp_path / "package-name.txt"
    apk_file = tmp_path / "bad.apk"
    pkg_file.write_bytes(b"\n")
    with ZipFile(apk_file, mode="w") as zfp:
        zfp.write(str(pkg_file), "package-name.txt")
    with raises(ADBSessionError, match="Failed to install"):
        session.install(apk_file)
    # good apk
    pkg_file = tmp_path / "package-name.txt"
    apk_file = tmp_path / "test.apk"
    syms_path = tmp_path / "symbols"
    syms_path.mkdir()
    pkg_file.write_bytes(b"test-package.blah.foo\n")
    with ZipFile(apk_file, mode="w") as zfp:
        zfp.write(str(pkg_file), "package-name.txt")
    assert session.install(apk_file)
    # get package name failed
    mocker.patch("fxpoppet.adb_session.ADBSession.get_package_name", return_value=None)
    with raises(ADBSessionError, match="Could not find APK package name"):
        session.install(apk_file)


def test_adb_session_uninstall(mocker):
    """test ADBSession.uninstall()"""

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "uninstall":
            if cmd[1] == "org.test.preinstalled":
                return ADBResult(0, "Success")
            if cmd[1] == "org.test.unknown":
                return ADBResult(1, "Failure [DELETE_FAILED_INTERNAL_ERROR]")
        raise AssertionError(f"unexpected command {cmd!r}")

    device = ADBDevice(mocker.Mock(spec_set=ADBWrapper), "fake-serial")
    device.adb.call.side_effect = fake_call
    session = ADBSession(device)
    assert not session.uninstall("org.test.unknown")
    assert session.uninstall("org.test.preinstalled")


def test_adb_session_get_pid(mocker):
    """test ADBSession.get_pid()"""

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "shell":
            # strip "shell -n -T"
            shell_cmd = cmd[3:]
            if shell_cmd[0] == "pidof":
                if shell_cmd[1] == "org.test.preinstalled":
                    return ADBResult(0, "1337")
                return ADBResult(1, "")
        raise AssertionError(f"unexpected command {cmd!r}")

    device = ADBDevice(mocker.Mock(spec_set=ADBWrapper), "fake-serial")
    device.adb.call.side_effect = fake_call
    session = ADBSession(device)
    assert session.get_pid("org.test.unknown") is None
    assert session.get_pid("org.test.preinstalled") == 1337


def test_adb_session_is_installed(mocker):
    """test ADBSession.is_installed()"""

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "shell":
            # strip "shell -n -T"
            shell_cmd = cmd[3:]
            if shell_cmd[0] == "pm":
                assert shell_cmd[1] == "list"
                assert shell_cmd[2] == "packages"
                return ADBResult(
                    0,
                    "package:org.mozilla.fennec_aurora\n"
                    "package:org.test.preinstalled\n"
                    "package:com.android.phone\n"
                    "package:com.android.shell",
                )
        raise AssertionError(f"unexpected command {cmd!r}")

    device = ADBDevice(mocker.Mock(spec_set=ADBWrapper), "fake-serial")
    device.adb.call.side_effect = fake_call
    session = ADBSession(device)
    assert not session.is_installed("org.test.unknown")
    assert session.is_installed("org.test.preinstalled")


def test_adb_session_packages(mocker):
    """test ADBSession.packages()"""

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "shell":
            # strip "shell -n -T"
            shell_cmd = cmd[3:]
            if shell_cmd[0] == "pm":
                assert shell_cmd[1] == "list"
                assert shell_cmd[2] == "packages"
                return ADBResult(
                    0,
                    "package:org.mozilla.fennec_aurora\n"
                    "package:org.test.preinstalled\n"
                    "package:com.android.phone\n"
                    "package:com.android.shell",
                )
        raise AssertionError(f"unexpected command {cmd!r}")

    device = ADBDevice(mocker.Mock(spec_set=ADBWrapper), "fake-serial")
    device.adb.call.side_effect = fake_call
    session = ADBSession(device)
    pkgs = tuple(session.packages)
    assert len(pkgs) == 4
    assert "com.android.phone" in pkgs
    assert "com.android.shell" in pkgs
    assert "org.mozilla.fennec_aurora" in pkgs
    assert "org.test.preinstalled" in pkgs


def test_adb_session_collect_logs(mocker):
    """test ADBSession.collect_logs()"""

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "logcat":
            assert cmd[1] == "-d"
            assert cmd[2] == "*:I"
            if len(cmd) == 4:
                assert cmd[-1].startswith("--pid=")
                pid = int(cmd[-1].split("=")[-1])
            else:
                pid = -1
            output = []
            if pid in (-1, 9990):
                output += [
                    "07-27 12:10:15.414  9990  9990 W fake log",
                    "07-27 12:10:15.430  9990  9990 I fake log",
                    "07-27 12:10:15.442  9990  4714 I fake log",
                    "07-27 12:10:15.505  9990  4713 E fake log",
                    "07-27 12:10:15.520  9990  4719 I fake log",
                    "07-27 12:10:15.529  9990  4707 W fake log",
                    "07-27 12:10:15.533  9990  4714 E fake log",
                ]
            if pid == -1:
                output += [
                    "07-27 12:39:27.188  3049  3049 W fake log",
                    "07-27 12:39:27.239  1887  1994 I fake log",
                    "07-27 12:39:27.286  2767  7142 I fake log",
                    "07-27 12:39:27.441  7128  7128 I fake log",
                ]
            return ADBResult(0, "\n".join(output))
        raise AssertionError(f"unexpected command {cmd!r}")

    device = ADBDevice(mocker.Mock(spec_set=ADBWrapper), "fake-serial")
    device.adb.call.side_effect = fake_call
    session = ADBSession(device)
    # test connected
    assert len(session.collect_logs().splitlines()) == 11
    assert len(session.collect_logs(9990).splitlines()) == 7
    assert not session.collect_logs(1111).splitlines()
    # test not connected
    device.adb.call.reset_mock(side_effect=True)
    device.adb.call.return_value = None
    assert session.collect_logs() is None


def test_adb_session_open_files(mocker):
    """test ADBSession.open_files()"""

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] != "shell":
            raise AssertionError(f"unexpected command {cmd!r}")
        # strip "shell -n -T"
        shell_cmd = cmd[3:]
        if shell_cmd[0] == "lsof":
            if len(shell_cmd) == 3:
                assert shell_cmd[1].startswith("-p")
            return ADBResult(
                0,
                "COMMAND     PID    USER   FD      TYPE   DEVICE  SIZE/OFF"
                "       NODE NAME\n"
                "init          1    root  cwd   unknown                   "
                "            /proc/1/cwd (readlink: Permission denied)\n"
                "lsof      15988   shell  cwd       DIR     0,13       780"
                "       4234 /\n"
                "lsof      15988   shell  txt       REG      8,1    432284"
                "    1696174 /system/bin/toybox\n"
                "lsof      15988   shell    4r      DIR      0,4         0"
                "     120901 /proc/15988/fd\n"
                "a.fennec_  9991  u0_a80   98r      REG      8,1    306672"
                "    1696611 /system/fonts/blah.ttf\n"
                "a.fennec_  9990  u0_a80  cwd       DIR     0,13       780"
                "       4234 /\n"
                "a.fennec_  9990  u0_a80  txt       REG      8,1     17948"
                "    1695879 /system/bin/app_process32\n"
                "a.fennec_  9990  u0_a80  mem   unknown                   "
                "            /dev/ashmem/dalvik-main space (deleted)\n"
                "a.fennec_  9990  u0_a80  mem       CHR    10,58          "
                "       4485 /dev/binder\n"
                "a.fennec_  9990  u0_a80  mem   unknown                   "
                "            /dev/ashmem/dalvik-allocspace zygote / x 0 (deleted)\n"
                "a.fennec_  9990  u0_a80  mem       REG      8,1    152888"
                "    1704079 /system/lib/libexpat.so\n"
                "a.fennec_  9990  u0_a80   54u      REG      8,1    329632"
                "    1769879 /data/data/org.mozilla.fennec_aurora/files/mozilla/a.defau"
                "lt/browser.db-wal\n"
                "a.fennec_  9990  u0_a80   55u     IPv6                0t0"
                "      44549 TCP []:49232->[]:443 (ESTABLISHED)\n"
                "a.fennec_  9990  u0_a80   75w     FIFO      0,9       0t0"
                "      44634 pipe:[44634]\n"
                "a.fennec_  9990  u0_a80   76u     sock                0t0"
                "      44659 socket:[44659]\n"
                "a.fennec_  9990  u0_a80   95u      REG      8,1     98304"
                "    1769930 /data/data/org.mozilla.fennec_aurora/files/mozilla/a.defau"
                "lt/permissions.sqlite\n"
                "a.fennec_  9990  u0_a80   98r      REG      8,1    306672"
                "    1696611 /system/fonts/Roboto-Regular.ttf\n"
                "a.fennec_  9990  u0_a80  122u      CHR    10,59       0t0"
                "       4498 /dev/ashmem\n"
                "a.fennec_  9990  u0_a80  123u     IPv4                0t0"
                "      44706 UDP :1900->:0\n"
                "a.fennec_  9990  u0_a80  125u     0000     0,10       0t0"
                "       3655 anon_inode:[eventpoll]\n"
                "a.fennec_  9990  u0_a80  126u     IPv4                0t0"
                "      44773 TCP :58190->:443 (ESTABLISHED)\n"
                "a.fennec_  9990  u0_a80  128u     unix                0t0"
                "      44747 socket\n"
                "a.fennec_  9990  u0_a80  130u     IPv4                0t0"
                "      44840 TCP :35274->:443 (SYN_SENT)\n",
            )
        if shell_cmd[0] == "ps":
            assert "--ppid" in shell_cmd
            assert "9990" in shell_cmd
            return ADBResult(
                0,
                "PID   PPID  RSS  NAME\n9991  9990  3331 org.mozilla.fennec_aurora\n",
            )
        raise AssertionError(f"unexpected command {cmd!r}")

    device = ADBDevice(mocker.Mock(spec_set=ADBWrapper), "fake-serial")
    device.adb.call.side_effect = fake_call
    session = ADBSession(device)
    # list all open files
    assert len(tuple(session.open_files())) == 7
    # list process specific open files
    assert len(tuple(session.open_files(pid=9990))) == 5
    # list process and children specific open files
    assert len(tuple(session.open_files(pid=9990, children=True))) == 6
    with raises(AssertionError):
        tuple(session.open_files(pid=None, children=True))
    # list open files with "files" args for coverage
    assert any(session.open_files(files=["test"]))


def test_adb_session_get_procs(mocker):
    """test ADBSession._get_procs()"""

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "shell":
            # strip "shell -n -T"
            shell_cmd = cmd[3:]
            if shell_cmd[0] == "ps":
                output = ["PID   PPID  RSS  NAME\n"]
                if shell_cmd[-1] == "-A":
                    output += [
                        "1     0     2208   /init\n",
                        "a     a     a      invalid.for.coverage\n",
                        "1242  2     0      kswapd0\n",
                        "1337  1772  1024   org.test.preinstalled\n",
                        "1338  1337  1024   org.test.child\n",
                        "1772  1     122196 zygote\n",
                        "2158  1758  0      sdcard\n",
                        "1773  1     9624   /system/bin/audioserver\n",
                        "5847  1     2348   /sbin/adbd\n",
                        "9990  1772  128064 org.mozilla.fennec_aurora\n",
                        "5944  5847  6280   ps\n",
                    ]
                elif "--ppid" in shell_cmd:
                    output.append("9991  9990  3332   org.mozilla.fennec_aurora\n")
                else:
                    output.append("9990  1772  128064 org.mozilla.fennec_aurora\n")
                return ADBResult(0, "".join(output))
        raise AssertionError(f"unexpected command {cmd!r}")

    device = ADBDevice(mocker.Mock(spec_set=ADBWrapper), "fake-serial")
    device.adb.call.side_effect = fake_call
    session = ADBSession(device)
    assert len(tuple(session._get_procs())) == 10
    dev_procs = tuple(session._get_procs(pid=9990))
    assert len(dev_procs) == 1
    assert dev_procs[0].pid == 9990
    dev_procs = tuple(session._get_procs(pid_children=9990))
    assert len(dev_procs) == 1
    assert dev_procs[0].pid == 9991


def test_adb_session_push(tmp_path, mocker):
    """test ADBSession.push()"""

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "push":
            assert "test.txt" in cmd[1]
            assert cmd[2] == "dst"
            return ADBResult(0, " pushed. ")
        raise AssertionError(f"unexpected command {cmd!r}")

    device = ADBDevice(mocker.Mock(spec_set=ADBWrapper), "fake-serial")
    device.adb.call.side_effect = fake_call
    session = ADBSession(device)
    with raises(FileNotFoundError):
        session.push(Path("not_a_file"), "dst")
    push_file = tmp_path / "test.txt"
    push_file.write_bytes(b"test\n")
    assert session.push(push_file, "dst")


def test_adb_session_pull(mocker):
    """test ADBSession.pull()"""

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "pull":
            assert cmd[1] == "src"
            assert cmd[2] == "dst"
            return ADBResult(0, " pulled. ")
        raise AssertionError(f"unexpected command {cmd!r}")

    device = ADBDevice(mocker.Mock(spec_set=ADBWrapper), "fake-serial")
    device.adb.call.side_effect = fake_call
    session = ADBSession(device)
    assert session.pull("src", "dst")


def test_adb_session_clear_log(mocker):
    """test ADBSession.clear_log()"""

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "logcat":
            assert cmd[1] == "--clear"
            return ADBResult(0, "")
        raise AssertionError(f"unexpected command {cmd!r}")

    device = ADBDevice(mocker.Mock(spec_set=ADBWrapper), "fake-serial")
    device.adb.call.side_effect = fake_call
    session = ADBSession(device)
    assert session.clear_logs()


def test_adb_session_listdir(mocker):
    """test ADBSession.listdir()"""

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "shell":
            # strip "shell -n -T"
            shell_cmd = cmd[3:]
            if shell_cmd[0] == "ls":
                assert shell_cmd[1] == "-A"
                if shell_cmd[2] == "missing-dir":
                    return ADBResult(1, "")
                return ADBResult(0, "test")
        raise AssertionError(f"unexpected command {cmd!r}")

    device = ADBDevice(mocker.Mock(spec_set=ADBWrapper), "fake-serial")
    device.adb.call.side_effect = fake_call
    session = ADBSession(device)
    with raises(FileNotFoundError):
        session.listdir("missing-dir")
    dir_list = tuple(str(x) for x in session.listdir("fake-dir"))
    assert len(dir_list) == 1
    assert "test" in dir_list
    # device connection failure
    device.adb.call.side_effect = (None,)
    assert not session.listdir("fake-dir")


def test_adb_session_process_exists(mocker):
    """test ADBSession.process_exists()"""

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "shell":
            # strip "shell -n -T"
            shell_cmd = cmd[3:]
            if shell_cmd[0] == "ps":
                assert "9990" in shell_cmd
                return ADBResult(0, "PID\n9990\n\n")
        raise AssertionError(f"unexpected command {cmd!r}")

    device = ADBDevice(mocker.Mock(spec_set=ADBWrapper), "fake-serial")
    device.adb.call.side_effect = fake_call
    session = ADBSession(device)
    assert session.process_exists(9990)


def test_adb_session_aapt_check(mocker, tmp_path):
    """test ADBSession._aapt_check()"""
    fake_aapt_sys = tmp_path / "aapt-sys"
    fake_aapt_sys.touch()
    # use system aapt
    mocker.patch("fxpoppet.adb_session.ANDROID_SDK_ROOT", tmp_path)
    mocker.patch("fxpoppet.adb_session.which", return_value=str(fake_aapt_sys))
    assert ADBSession._aapt_check() == str(fake_aapt_sys)
    # use recommended aapt
    (tmp_path / "android-9").mkdir()
    fake_aapt = tmp_path / "android-9" / "aapt"
    fake_aapt.touch()
    mocker.patch("fxpoppet.adb_session.ANDROID_SDK_ROOT", tmp_path)
    assert ADBSession._aapt_check() == str(fake_aapt)
    # aapt not installed
    mocker.patch("fxpoppet.adb_session.ANDROID_SDK_ROOT", tmp_path / "missing")
    mocker.patch("fxpoppet.adb_session.which", return_value=None)
    with raises(OSError, match="Please install AAPT"):
        assert ADBSession._aapt_check()


def test_adb_session_get_package_name(mocker, tmp_path):
    """test ADBSession.get_package_name()"""
    mocker.patch("fxpoppet.adb_session.ADBSession._aapt_check", return_value=b"fake")
    mocker.patch("fxpoppet.adb_session.check_output", return_value=b"")
    with raises(FileNotFoundError):
        ADBSession.get_package_name(Path("/fake/path"))
    fake_apk = tmp_path / "fake.apk"
    fake_apk.touch()
    assert ADBSession.get_package_name(fake_apk) is None
    output = (
        b"package: name='org.mozilla.fennec_aurora' versionCode='2015624653'"
        b" versionName='68.0a1' platformBuildVersionName=''\n"
        b"install-location:'internalOnly'\n"
        b"sdkVersion:'16'\n"
        b"targetSdkVersion:'28'\n"
        b"uses-permission: name='android.permission.READ_SYNC_SETTINGS'\n"
        b"uses-permission:"
        b" name='org.mozilla.fennec_aurora_fxaccount.permission.PER_ACCOUNT_TYPE'\n"
        b"application-label:'Firefox Nightly'\n"
        b"application-label-en-GB:'Firefox Nightly'\n"
        b"application-icon-240:'res/mipmap-anydpi-v26/ic_launcher.xml'\n"
        b"application-icon-65535:'res/mipmap-anydpi-v26/ic_launcher.xml'\n"
        b"application:"
        b" label='Firefox Nightly' icon='res/mipmap-anydpi-v26/ic_launcher.xml'\n"
        b"application-debuggable\n"
        b"feature-group: label=''\n"
        b"  uses-gl-es: '0x20000'\n"
        b"  uses-feature-not-required: name='android.hardware.audio.low_latency'\n"
        b"  uses-feature: name='android.hardware.touchscreen'\n"
        b"  uses-feature: name='android.hardware.location.network'\n"
        b"  uses-implied-feature: name='android.hardware.location.network'"
        b" reason='requested android.permission.ACCESS_COARSE_LOCATION permission'\n"
        b"  uses-feature: name='android.hardware.wifi'\n"
        b"  uses-implied-feature: name='android.hardware.wifi'"
        b" reason='requested android.permission.ACCESS_WIFI_STATE permission, and"
        b" requested android.permission.CHANGE_WIFI_STATE permission'\n"
        b"provides-component:'app-widget'\n"
        b"main\n"
        b"other-activities\n"
        b"other-receivers\n"
        b"other-services\n"
        b"supports-screens: 'small' 'normal' 'large' 'xlarge'\n"
        b"supports-any-density: 'true'\n"
        b"locales: '--_--' 'ca' ' 'en-GB' 'zh-HK' 'zh-CN' 'en-IN' 'pt-BR' 'es-US'"
        b" 'pt-PT' 'en-AU' 'zh-TW'\n"
        b"densities: '120' '160' '240' '320' '480' '640' '65534' '65535'\n"
        b"native-code: 'x86'"
    )
    mocker.patch("fxpoppet.adb_session.check_output", return_value=output)
    assert ADBSession.get_package_name(fake_apk) == "org.mozilla.fennec_aurora"


def test_adb_session_realpath(mocker):
    """test ADBSession.realpath()"""

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "shell":
            # strip "shell -n -T"
            shell_cmd = cmd[3:]
            if shell_cmd[0] == "realpath":
                if shell_cmd[1] == "missing/path":
                    return ADBResult(1, "")
                return ADBResult(0, "existing/path")
        raise AssertionError(f"unexpected command {cmd!r}")

    device = ADBDevice(mocker.Mock(spec_set=ADBWrapper), "fake-serial")
    device.adb.call.side_effect = fake_call
    session = ADBSession(device)
    with raises(FileNotFoundError):
        session.realpath(PurePosixPath("missing/path"))
    assert str(session.realpath(PurePosixPath("existing/path"))) == "existing/path"
    # device connection failure
    device.adb.call.side_effect = (None,)
    assert session.realpath(PurePosixPath("existing/path")) is None


def test_adb_session_reverse(mocker):
    """test ADBSession.reverse()"""

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "reverse":
            return ADBResult(0, "")
        raise AssertionError(f"unexpected command {cmd!r}")

    device = ADBDevice(mocker.Mock(spec_set=ADBWrapper), "fake-serial")
    device.adb.call.side_effect = fake_call
    session = ADBSession(device)
    assert session.reverse(1234, 1235)


def test_adb_session_reverse_remove(mocker):
    """test ADBSession.reverse_remove()"""

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "reverse":
            if cmd[1] == "--remove":
                assert cmd[2].startswith("tcp:")
            elif cmd[1] == "--remove-all":
                pass
            else:
                raise AssertionError(f"unexpected command {cmd!r}")
            return ADBResult(0, "")
        raise AssertionError(f"unexpected command {cmd!r}")

    device = ADBDevice(mocker.Mock(spec_set=ADBWrapper), "fake-serial")
    device.adb.call.side_effect = fake_call
    session = ADBSession(device)
    assert session.reverse_remove()
    assert session.reverse_remove(remote=1025)


def test_adb_session_airplane_mode(mocker):
    """test ADBSession.airplane_mode()"""

    def fake_call(cmd, **_kw):
        assert cmd
        if cmd[0] == "shell":
            # strip "shell -n -T"
            shell_cmd = cmd[3:]
            if shell_cmd[0] == "settings":
                if shell_cmd[1] == "get":
                    assert shell_cmd[2] == "global"
                    assert shell_cmd[3] == "airplane_mode_on"
                    return ADBResult(0, "1")
                if shell_cmd[1] == "put":
                    assert shell_cmd[2] == "global"
                    assert shell_cmd[3] == "airplane_mode_on"
                    assert shell_cmd[4] in "01"
                    return ADBResult(0, "")
            if shell_cmd[0] == "am":
                assert shell_cmd[1] == "broadcast"
                assert shell_cmd[2] == "-a"
                assert shell_cmd[3] == "android.intent.action.AIRPLANE_MODE"
                return ADBResult(0, "")
        raise AssertionError(f"unexpected command {cmd!r}")

    device = ADBDevice(mocker.Mock(spec_set=ADBWrapper), "fake-serial")
    device.adb.call.side_effect = fake_call
    session = ADBSession(device)
    session.airplane_mode = False
    session.airplane_mode = True
    assert session.airplane_mode


def test_adb_session_sanitizer_options(mocker):
    """test ADBSession.sanitizer_options()"""

    def fake_install_file(_, src, dst, **_kw):
        src = Path(src)
        assert src.name == "asan.options.gecko"
        assert src.read_text(encoding="ascii") in ("a=1:b=2", "b=2:a=1")
        assert str(dst) == str(DEVICE_TMP)

    mocker.patch("fxpoppet.adb_session.ADBSession.install_file", fake_install_file)
    device = mocker.Mock(spec_set=ADBDevice)
    session = ADBSession(device)
    session.sanitizer_options("asan", {"a": "1", "b": "2"})


def test_adb_session_install_file(mocker):
    """test ADBSession.install_file()"""
    mocker.patch("fxpoppet.adb_session.ADBSession.push", autospec=True)
    device = mocker.Mock(spec_set=ADBDevice)
    session = ADBSession(device)
    session.install_file(
        Path("a/b"), PurePosixPath("/sdcard"), mode="777", context="foo"
    )
