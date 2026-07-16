"""Path handling helper (pre-rename)."""


def read_config(base_dir, name):
    path = base_dir + "/" + name
    with open(path) as fh:
        return fh.read()
