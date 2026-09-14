"""Regenerate the HDF5 fixtures with real h5py and Keras.

Not run by the test suite: CI has neither library, which is the reason the
fixtures are committed. Requires `pip install h5py keras jax scipy`.

    KERAS_BACKEND=numpy python generate.py

Every path stored in these files points to /nonexistent/..., and nothing in them
runs on load except the Lambda in keras-lambda.h5, which doubles its input.
Each structure is written twice: libver "earliest" gives superblock v0 with
version 1 object headers, libver "latest" gives superblock v3 with version 2.
"""
import os
from pathlib import Path

os.environ.setdefault("KERAS_BACKEND", "numpy")

import h5py  # noqa: E402
import keras  # noqa: E402
import numpy as np  # noqa: E402

OUT = Path(__file__).resolve().parent

for libver, tag in (("earliest", "v0"), ("latest", "v3")):
    with h5py.File(OUT / f"plain-{tag}.h5", "w", libver=libver) as f:
        f.create_dataset("group/weights", data=np.arange(16, dtype="f4"))
        f.attrs["note"] = "benign"
    with h5py.File(OUT / f"extlink-{tag}.h5", "w", libver=libver) as f:
        f["leak"] = h5py.ExternalLink("/nonexistent/secret.h5", "/data")
    with h5py.File(OUT / f"extstorage-{tag}.h5", "w", libver=libver) as f:
        f.create_dataset("leak", shape=(4,), dtype="u1",
                         external=[("/nonexistent/secret.bin", 0, 4)])
    with h5py.File(OUT / f"vds-{tag}.h5", "w", libver=libver) as f:
        layout = h5py.VirtualLayout(shape=(4,), dtype="u1")
        layout[:] = h5py.VirtualSource("/nonexistent/secret.h5", "data", shape=(4,))
        f.create_virtual_dataset("leak", layout)
    with h5py.File(OUT / f"shapebomb-{tag}.h5", "w", libver=libver) as f:
        f.create_dataset("bomb", shape=(10**6, 10**6), dtype="f8", chunks=(1, 1024))

# More than a handful of links makes a recent library keep a group's links in a fractal
# heap instead of a symbol table. An external link hidden among them used to be invisible.
with h5py.File(OUT / "dense-links.h5", "w", libver="latest") as f:
    group = f.create_group("many")
    for i in range(32):
        group.create_dataset(f"d{i:02d}", data=np.zeros(2, dtype="u1"))
    group["leak"] = h5py.ExternalLink("/nonexistent/secret.h5", "/data")

# The same for attributes: past a handful they move into a fractal heap as well, whose
# root here is an indirect block indexed by a B-tree one level deep.
with h5py.File(OUT / "dense-attrs.h5", "w", libver="latest") as f:
    dataset = f.create_dataset("x", data=np.arange(4, dtype="u1"))
    for i in range(32):
        dataset.attrs[f"attr{i:02d}"] = f"value {i}"

# A user block pushes the superblock to offset 512 or 1024. Whatever sits in front of
# it is invisible to HDF5 itself, so a scanner that only looks at offset 0 sees nothing.
for user_block in (512, 1024):
    path = OUT / f"userblock-{user_block}.h5"
    with h5py.File(path, "w", userblock_size=user_block) as f:
        f.create_dataset("weights", data=np.arange(4, dtype="f4"))
        f["leak"] = h5py.ExternalLink("/nonexistent/secret.h5", "/data")
    with open(path, "r+b") as fh:
        fh.write(b"#!/bin/sh\n# anything at all can sit in a user block\n")

keras.Sequential([keras.Input((4,)), keras.layers.Dense(2, name="dense_a")]).save(
    OUT / "keras-plain.h5")
keras.Sequential([keras.Input((4,)), keras.layers.Lambda(lambda x: x * 2, name="double")]).save(
    OUT / "keras-lambda.h5")

# The same Lambda with its storage changed rather than its contents: padding the root
# group pushes model_config out of the object header and into the fractal heap. While
# that heap went unread the file reported only "not checked", so this is the fixture
# that proves the payload path and not merely the structure. It copies the config Keras
# wrote just above instead of asking Keras for it again.
with h5py.File(OUT / "keras-lambda.h5", "r") as src:
    lambda_config = src.attrs["model_config"]
with h5py.File(OUT / "keras-lambda-dense.h5", "w", libver="latest") as f:
    f.attrs["model_config"] = lambda_config
    for i in range(32):
        f.attrs[f"pad{i:02d}"] = f"value {i}"

# And again with enough padding to push the name index to depth 2, where a child pointer
# carries a second count whose width depends on the size of the subtree beneath it.
with h5py.File(OUT / "keras-lambda-deep.h5", "w", libver="latest") as f:
    f.attrs["model_config"] = lambda_config
    for i in range(511):
        f.attrs[f"pad{i:04d}"] = "v" * 8

print("\n".join(sorted(p.name for p in OUT.glob("*.h5"))))
