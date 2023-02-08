from pathlib import Path
from shutil import copyfile

from invoke import Context


class LocalContext(Context):
    def put(self, local, remote=None):
        self._cp(local, remote, Path.cwd(), self.cwd)

    def get(self, remote, local=None):
        self._cp(remote, local, self.cwd, Path.cwd())

    def _parse(self, other, rel_to, change_parent=None):
        op = Path(other)
        if op.is_absolute():
            if change_parent and op.is_relative_to(change_parent):
                return Path(rel_to, op.relative_to(change_parent))
            else:
                return op
        return Path(rel_to, op)

    def _cp(self, source, target, source_rel, target_rel):
        true_target = self._parse(target or source, target_rel, source_rel)
        true_target.parent.mkdir(exist_ok=True, parents=True)
        copyfile(self._parse(source, source_rel), true_target)
