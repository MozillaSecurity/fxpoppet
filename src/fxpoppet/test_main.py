# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import DEBUG, INFO

from pytest import mark, raises

from .adb_process import Reason
from .adb_session import ADBSessionError
from .main import configure_logging, main, parse_args


@mark.parametrize(
    "env, log_level",
    [
        # default log level
        ("0", INFO),
        # debug log level
        ("0", DEBUG),
        # enable debug log level via env
        ("1", INFO),
        # enable debug log level via env
        ("TRUE", INFO),
    ],
)
def test_configure_logging_01(mocker, env, log_level):
    """test configure_logging()"""
    config = mocker.patch("fxpoppet.main.basicConfig", autospec=True)
    mocker.patch("fxpoppet.main.getenv", autospec=True, return_value=env)
    configure_logging(log_level)
    assert config.call_count == 1
    if env != "0":
        assert config.call_args[-1]["level"] == DEBUG
    else:
        assert config.call_args[-1]["level"] == log_level


@mark.parametrize(
    "args, msg",
    [
        (["--install", "missing"], "error: Invalid APK 'missing'"),
        (["--launch", "missing"], "error: Invalid APK 'missing'"),
        (["--prep", "missing"], "error: Invalid APK 'missing'"),
    ],
)
def test_parse_01(capsys, args, msg):
    """test parse_args()"""
    with raises(SystemExit):
        parse_args(argv=["-s", "fake-serial", *args])
    assert msg in capsys.readouterr()[1]


def test_parse_02(tmp_path):
    """test parse_args()"""
    apk = tmp_path / "fake.apk"
    apk.touch()
    assert parse_args(argv=["-s", "fake-serial", "--prep", str(apk)])


def test_parse_03(capsys, mocker, tmp_path):
    """test parse_args() - missing --serial"""
    device_cls = mocker.patch("fxpoppet.main.ADBWrapper", autospec=True)
    device_cls.devices.return_value = {
        "emu-1234": "device",
        "emu-5678": "device",
    }
    apk = tmp_path / "fake.apk"
    apk.touch()
    with raises(SystemExit):
        parse_args(argv=["--prep", str(apk)])
    assert "error: Multiple devices detected." in capsys.readouterr()[1]

    device_cls.reset_mock()
    device_cls.devices.return_value = {"emu-1234": "device"}
    args = parse_args(argv=["--prep", str(apk)])
    assert args.serial == "emu-1234"

    device_cls.devices.return_value = {}
    with raises(SystemExit):
        parse_args(argv=["--prep", str(apk)])
    assert "error: No device detected." in capsys.readouterr()[1]


def test_main_connect_failed(mocker):
    """test main() - session connect failed"""
    session_cls = mocker.patch("fxpoppet.main.ADBSession", autospec=True)
    session_cls.connect.side_effect = ADBSessionError("test")
    args = mocker.Mock(non_root=False, prep=None)
    assert main(args) == 1
    assert session_cls.connect.call_count == 1


def test_main_airplane_mode(mocker):
    """test main() - airplane mode"""
    session_cls = mocker.patch("fxpoppet.main.ADBSession", autospec=True)
    args = mocker.Mock(
        airplane_mode=1,
        launch=None,
        install=None,
        non_root=False,
        prep=None,
    )
    assert main(args) == 0
    assert session_cls.connect.call_count == 1
    assert session_cls.connect.return_value.airplane_mode == 1


@mark.parametrize(
    "pkg, install, result",
    [
        # success
        ("test", "test", 0),
        # bad apk, failed to lookup name
        (None, None, 1),
        # install failed
        ("test", None, 1),
    ],
)
def test_main_install(mocker, tmp_path, pkg, install, result):
    """test main() - install"""
    session_cls = mocker.patch("fxpoppet.main.ADBSession", autospec=True)
    session_cls.get_package_name.return_value = pkg
    session_obj = session_cls.connect.return_value
    session_obj.install.return_value = install
    apk = tmp_path / "fake.apk"
    (tmp_path / "llvm-symbolizer").touch()
    args = mocker.Mock(
        airplane_mode=None,
        launch=None,
        install=apk,
        non_root=False,
        prep=None,
    )
    assert main(args) == result
    assert session_cls.connect.call_count == 1
    assert session_obj.install.call_count == (1 if pkg else 0)
    assert session_obj.install_file.call_count == (0 if result else 1)


@mark.parametrize(
    "pkg, result",
    [
        # success
        ("test", 0),
        # bad apk, failed to lookup name
        (None, 1),
    ],
)
def test_main_launch(mocker, tmp_path, pkg, result):
    """test main() - launch"""
    mocker.patch("fxpoppet.main.ADBProcess", autospec=True)
    session_cls = mocker.patch("fxpoppet.main.ADBSession", autospec=True)
    session_cls.get_package_name.return_value = pkg
    args = mocker.Mock(
        airplane_mode=None,
        launch=tmp_path / "fake.apk",
        install=None,
        non_root=False,
        prep=None,
        logs=tmp_path,
    )
    assert main(args) == result
    assert session_cls.connect.call_count == 1


def test_main_collect_logs(mocker, tmp_path):
    """test main() - launch collect logs"""
    proc_cls = mocker.patch("fxpoppet.main.ADBProcess", autospec=True)
    proc_cls.return_value.reason = Reason.ALERT
    mocker.patch("fxpoppet.main.ADBSession", autospec=True)
    args = mocker.Mock(
        airplane_mode=None,
        launch=tmp_path / "fake.apk",
        install=None,
        non_root=False,
        prep=None,
        logs=tmp_path,
    )
    assert main(args) == 0
    assert proc_cls.return_value.close.call_count == 1
    assert proc_cls.return_value.save_logs.call_count == 1
    assert proc_cls.return_value.cleanup.call_count == 1


def test_main_package_not_installed(mocker, tmp_path):
    """test main() - package not installed"""
    proc_cls = mocker.patch("fxpoppet.main.ADBProcess", autospec=True)
    proc_cls.side_effect = ADBSessionError("test package not installed")
    mocker.patch("fxpoppet.main.ADBSession", autospec=True)
    args = mocker.Mock(
        airplane_mode=None,
        launch=tmp_path / "fake.apk",
        install=None,
        non_root=False,
        prep=None,
        logs=tmp_path,
    )
    assert main(args) == 1
    assert proc_cls.return_value.launch.call_count == 0


def test_main_prep(mocker, tmp_path):
    """test main() - prep"""
    session_cls = mocker.patch("fxpoppet.main.ADBSession", autospec=True)
    args = mocker.Mock(
        airplane_mode=None,
        launch=None,
        install=None,
        non_root=False,
        prep=tmp_path / "fake.apk",
    )
    assert main(args) == 0
    assert session_cls.connect.call_count == 1
    session_obj = session_cls.connect.return_value
    assert session_obj.airplane_mode == 1
    assert session_obj.install.call_count == 1
