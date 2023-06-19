import os
import secrets
import sys
from base64 import urlsafe_b64decode as b64d
from base64 import urlsafe_b64encode as b64e
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from subprocess import check_call
from tempfile import TemporaryDirectory
from typing import Callable, Dict, Optional, Union

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.backend import Backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CONF_PATH = Path.home() / ".zimmauth"
LOCAL_HOST_NAMES_ENV_VAR = "ZAUTH_LOCAL_HOST_NAMES"


@dataclass
class EncryptBase:
    iterations: int = 100_000
    backend: Backend = field(default_factory=default_backend)
    length: int = 32
    algo: Callable = hashes.SHA256
    salt_length: int = 16

    def encrypt(self, message: bytes, password: str) -> str:
        salt = secrets.token_bytes(self.salt_length)
        key = self._derive_key(password, salt)
        token = b64d(Fernet(key).encrypt(message))
        return b64e(b"%b%b" % (salt, token)).hex(" ")

    def decrypt(self, hex_token: str, password: str) -> bytes:
        decoded = b64d(bytes.fromhex(hex_token))
        sl = self.salt_length
        salt, token = decoded[:sl], b64e(decoded[sl:])
        key = self._derive_key(password, salt)
        return Fernet(key).decrypt(token)

    def encrypt_str(self, message: str, password: str) -> str:
        return self.encrypt(message.encode(), password)

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=self.algo(),
            length=self.length,
            salt=salt,
            iterations=self.iterations,
            backend=self.backend,
        )
        return b64e(kdf.derive(password.encode()))


@dataclass
class S3Auth:
    key: str
    secret: str
    endpoint: Optional[str] = None

    def __repr__(self) -> str:
        return f"Auth {self.key[:2]}"


@dataclass
class S3Remote:
    bucket_name: str
    auth: S3Auth

    def get_dvc_string(self):
        return f"s3://{self.bucket_name}"

    def add_dvc_modifies(self, _):
        for k, v in [
            ("access_key_id", self.auth.key),
            ("secret_access_key", self.auth.secret),
            ("endpointurl", self.auth.endpoint),
        ]:
            if v:
                yield k, v


@dataclass
class SSHRemote:
    host: str
    path: str = ""
    user: str = field(default_factory=os.getlogin)
    port: int | None = None
    rsa_key: Optional[str] = None

    def __repr__(self) -> str:
        return f"SSH: {self.host}:/{self.path}"

    def get_dvc_string(self):
        if self.host in _get_local_names():
            return self.path
        return f"ssh://{self.user}@{self.host}{self.path}"

    def add_dvc_modifies(self, key_store: Path):
        if self.host in _get_local_names():
            return []
        if self.rsa_key:
            yield ("keyfile", (key_store / self.rsa_key).as_posix())
        if self.port:
            yield ("port", str(self.port))


class ZimmAuth:
    def __init__(self, dic: dict) -> None:
        def _pop(key):
            return dic.pop(key, {})

        auths = {k: S3Auth(**v) for k, v in _pop("keys").items()}
        _ssh_hosts = _pop("ssh")
        self._rsa_keys = _pop("rsa-keys")

        self._s3_remotes: Dict[str, S3Remote] = {}
        self._ssh_remotes: Dict[str, SSHRemote] = {}

        for k, r in dic.items():
            if "key" in r.keys():
                self._s3_remotes[k] = S3Remote(k, auths[r["key"]])
            if "connection" in r.keys():
                ssh_conf = _ssh_hosts[r.pop("connection")]
                remote = SSHRemote(**ssh_conf, **r)
                self._ssh_remotes[k] = remote

    def get_auth(self, remote_id: str) -> S3Auth:
        return self._s3_remotes[remote_id].auth

    @contextmanager
    def get_fabric_connection(self, remote_name: str):
        from fabric import Connection

        from .local_conn import LocalContext

        tmp_dir = TemporaryDirectory()
        ssh_rem = self._ssh_remotes[remote_name]
        if ssh_rem.host in _get_local_names():
            ctx = LocalContext()
        else:
            key_path = Path(tmp_dir.name, "key")
            c_kwargs = {}

            if ssh_rem.rsa_key:
                key = self._rsa_keys[ssh_rem.rsa_key]
                key_path.write_text(key)
                c_kwargs["key_filename"] = key_path.absolute().as_posix()

            ctx = Connection(
                host=ssh_rem.host,
                user=ssh_rem.user,
                port=ssh_rem.port,
                connect_kwargs=c_kwargs,
            )
        with ctx.cd(ssh_rem.path):
            yield ctx
        tmp_dir.cleanup()

    def dump_dvc(self, local=True, key_store=CONF_PATH, executable=sys.executable):
        for k, v in self._remotes.items():
            runbase = [executable, "-m", "dvc", "remote"]
            lflag = "--local" if local else "--global"
            remstr = v.get_dvc_string()
            check_call([*runbase, "add", lflag, "-f", k, remstr])
            for mod_k, mod_v in v.add_dvc_modifies(key_store):
                check_call([*runbase, "modify", lflag, k, mod_k, mod_v])

        self._dump_keys(key_store)

    def get_boto_bucket(self, remote_name):
        import boto3

        s3_rem = self._s3_remotes[remote_name]
        auth = s3_rem.auth

        return boto3.resource(
            "s3",
            endpoint_url=auth.endpoint,
            aws_access_key_id=auth.key,
            aws_secret_access_key=auth.secret,
        ).Bucket(s3_rem.bucket_name)

    @classmethod
    def from_env(cls, dic_env_var: str, pw_env_var: Optional[str] = None):
        import toml

        toml_str = os.environ.get(dic_env_var, "")
        if pw_env_var:
            assert toml_str, f"Nothing given for {dic_env_var}"
            toml_str = EncryptBase().decrypt(toml_str, os.environ[pw_env_var]).decode()

        return cls(toml.loads(toml_str))

    @staticmethod
    def dumps_dict(dic: dict, password: str):
        import toml

        return EncryptBase().encrypt_str(toml.dumps(dic), password)

    def _dump_keys(self, root: Path):
        root.mkdir(exist_ok=True, parents=True)
        for key_id, keystr in self._rsa_keys.items():
            key_path = root / key_id
            key_path.write_text(keystr)
            key_path.chmod(0o600)

    @property
    def _remotes(self) -> Dict[str, Union[S3Remote, SSHRemote]]:
        return {**self._s3_remotes, **self._ssh_remotes}


def _get_local_names():
    return os.environ.get(LOCAL_HOST_NAMES_ENV_VAR, "").split(";")
