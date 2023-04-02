import os
import tempfile
from pathlib import Path

import boto3
import moto
from cryptography.fernet import InvalidToken
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dvc.repo import Repo
from mockssh.server import Server
from pytest import fixture, raises

from zimmauth.core import LOCAL_HOST_NAMES_ENV_VAR, EncryptBase, ZimmAuth

TEST_USER = "zuzzer"
TEST_HOST = "zhost"


@fixture(scope="session")
def private_key_path():
    key = rsa.generate_private_key(
        backend=crypto_default_backend(), public_exponent=65537, key_size=2048
    )

    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.TraditionalOpenSSL,
        crypto_serialization.NoEncryption(),
    )
    with tempfile.TemporaryDirectory() as tmp_dir:
        key_path = Path(tmp_dir, "pkey")
        key_path.write_bytes(private_key)
        yield key_path


@fixture(scope="session")
def server(private_key_path: Path):
    users = {TEST_USER: private_key_path.as_posix()}
    with Server(users) as s:
        yield s


@fixture(scope="session")
def zauth_root():
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)


@fixture(scope="session")
def far_file():
    with tempfile.TemporaryDirectory() as tmp_path:
        ff = Path(tmp_path, "farf")
        ff.write_text("Faaar")
        yield ff


@fixture
def zauth(server: Server, private_key_path: Path, zauth_root: Path, tmp_path, far_file):
    test_dic = {
        "keys": {
            "s3-key-name-1": {"key": "XYZ", "secret": "XXX"},
            "s3-key-name-2": {"key": "XYZ", "secret": "XXX", "endpoint": "http"},
        },
        "rsa-keys": {"rsa-key-name": private_key_path.read_text()},
        "ssh": {
            "ssh-name-1": {
                "host": Server.host,
                "port": server.port,
                "user": TEST_USER,
                "rsa_key": "rsa-key-name",
            },
            "ssh-name-2": {
                "host": TEST_HOST,
                "rsa_key": "rsa-key-name",
                "user": TEST_USER,
            },
        },
        "bucket-1": {"key": "s3-key-name-1"},
        "bucket-2": {"key": "s3-key-name-2"},
        "ssh-conn-1": {"connection": "ssh-name-1", "path": zauth_root.as_posix()},
        "ssh-conn-2": {"connection": "ssh-name-1"},
        "ssh-conn-3": {"connection": "ssh-name-2", "path": far_file.parent.as_posix()},
    }
    return ZimmAuth(test_dic)


@fixture
def idiotic():
    # https://github.com/aio-libs/aiobotocore/issues/755
    # https://github.com/fsspec/s3fs/issues/357

    import aiobotocore.awsrequest
    import botocore.awsrequest
    import moto.core.botocore_stubber

    _OldBotoC = botocore.awsrequest.AWSResponse.content
    _Old = moto.core.botocore_stubber.MockRawResponse

    class RHMockResp(moto.core.botocore_stubber.MockRawResponse):
        raw_headers = {b"x-amz-bucket-region": b"region"}.items()

        async def read(self):
            return super().read()

    moto.core.botocore_stubber.MockRawResponse = RHMockResp
    botocore.awsrequest.AWSResponse.content = (
        aiobotocore.awsrequest.AioAWSResponse.content
    )
    botocore.awsrequest.AWSResponse._content_prop = (
        aiobotocore.awsrequest.AioAWSResponse._content_prop
    )
    yield
    botocore.awsrequest.AWSResponse.content = _OldBotoC
    moto.core.botocore_stubber.MockRawResponse = _Old


@fixture(scope="session")
def zauth_bucket():
    with moto.mock_s3():
        conn = boto3.resource("s3")
        conn.create_bucket(
            Bucket="bucket-1",
            CreateBucketConfiguration={"LocationConstraint": "us-west-1"},
        )
        yield conn


def test_ssh(zauth: ZimmAuth, zauth_root: Path):
    with zauth.get_fabric_connection("ssh-conn-1") as conn:
        assert conn.cwd == zauth_root.as_posix()

    with zauth.get_fabric_connection("ssh-conn-2") as conn:
        assert conn.cwd == ""
    assert "XXX" not in zauth._remotes.__repr__()


def test_env_loading():
    dic = {
        "rsa-keys": {"abc": "XYZ"},
        "keys": {"s31": {"key": "xy", "secret": "123"}},
        "buc1": {"key": "s31"},
    }
    test_pw = "Pw742"
    os.environ["__ZDIC"] = ZimmAuth.dumps_dict(dic, test_pw)
    os.environ["__ZPW"] = test_pw
    zauth = ZimmAuth.from_env("__ZDIC", "__ZPW")
    assert "abc" in zauth._rsa_keys.keys()
    assert zauth.get_auth("buc1").secret == "123"


def test_dvc(zauth: ZimmAuth, tmp_path: Path, far_file: Path, zauth_bucket, idiotic):
    cwd = Path.cwd()
    os.chdir(tmp_path)
    os.environ[LOCAL_HOST_NAMES_ENV_VAR] = TEST_HOST
    try:
        Repo.init(no_scm=True)
        zauth.dump_dvc(key_store=tmp_path / "keys")
        repo = Repo()
        kp = Path("sg")
        kp.write_text("ABC")
        repo.add(kp.as_posix())
        repo.push([kp.as_posix()], remote="ssh-conn-1")
        # repo.push([kp.as_posix()], remote="bucket-1") TODO maybe this will work again
        repo.push([kp.as_posix()], remote="ssh-conn-3")
        assert ["90"] == [f.name for f in far_file.parent.iterdir() if f != far_file]

    finally:
        os.chdir(cwd)


def test_boto(zauth: ZimmAuth, zauth_bucket: boto3, tmp_path: Path):
    bucket = zauth.get_boto_bucket("bucket-1")
    fpath = tmp_path / "testfile"
    dpath = tmp_path / "downloaded"
    fpath.write_text("fing")
    bucket.upload_file(fpath.as_posix(), "test-uploaded")
    bucket.download_file("test-uploaded", dpath.as_posix())
    assert dpath.read_text() == "fing"


def test_localize(zauth: ZimmAuth, tmp_path: Path, far_file: Path):
    tfile = tmp_path / "fing"
    ffile = tmp_path / "get"
    tfile.write_text("boo")
    in_cwd_file = Path("_file").absolute()
    in_cwd_file.write_text("botd")
    os.environ[LOCAL_HOST_NAMES_ENV_VAR] = TEST_HOST
    with zauth.get_fabric_connection("ssh-conn-3") as conn:
        conn.put(in_cwd_file)
        conn.put(tfile.as_posix(), "f2")
        conn.get(far_file, ffile)
    assert ffile.exists()
    assert (far_file.parent / in_cwd_file.name).read_text() == "botd"
    in_cwd_file.unlink()


def test_secret_base():
    eb = EncryptBase()
    pw = "TestPw"
    msg = "Some Msg"
    token_hex = eb.encrypt_str(msg, pw)
    assert msg.encode() == eb.decrypt(token_hex, pw)

    with raises(InvalidToken):
        eb.decrypt(token_hex, "Wrong")
