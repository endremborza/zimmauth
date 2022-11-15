from pathlib import Path
from shutil import copyfile

from invoke import Context


class LocalContext(Context):
    def put(self, local, remote=None):
        self._cp(local, remote, Path.cwd(), None)

    def get(self, remote, local=None):
        self._cp(remote, local, None, Path.cwd())

    def _parse(self, other, rel_to=None):
        op = Path(other)
        if op.is_absolute():
            return op
        return Path(rel_to or self.cwd, other)

    def _cp(self, source, target, source_rel, target_rel):
        true_target = self._parse(target or source, target_rel)
        true_target.parent.mkdir(exist_ok=True, parents=True)
        copyfile(self._parse(source, source_rel), true_target)
