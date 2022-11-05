from pathlib import Path
from shutil import copyfile

from invoke import Context


class LocalContext(Context):
    def put(self, local, remote=None):
        copyfile(self._parse(local), self._parse(remote or local))

    def get(self, remote, local=None):
        copyfile(self._parse(remote), self._parse(local or remote))

    def _parse(self, other):
        op = Path(other)
        if op.is_absolute():
            return op
        return Path(self.cwd, other)
