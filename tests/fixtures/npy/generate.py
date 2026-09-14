"""Regenerate the NumPy fixtures with real numpy.

Not run by the test suite, which is why the fixtures are committed; CI installs
only pytest and pyyaml. Requires `pip install numpy`.

    python generate.py

Nothing here is malicious. object.npy and object.npz hold ordinary Python
objects, which numpy stores as a pickle; the scanner reads that pickle's opcodes
and never loads it.
"""
from pathlib import Path

import numpy as np

OUT = Path(__file__).resolve().parent

# Ordinary arrays: these must produce no findings at all.
np.save(OUT / "float32.npy", np.arange(12, dtype="f4").reshape(3, 4))
np.save(OUT / "fortran.npy", np.asfortranarray(np.zeros((3, 3), dtype="f8")))
# A field literally called "Offset" would match a naive "O in descr" test.
np.save(OUT / "structured.npy", np.zeros(3, dtype=[("Offset", "<f4"), ("count", "<i8")]))
np.savez(OUT / "arrays.npz", x=np.ones(4, dtype="f4"), y=np.arange(3))
np.savez_compressed(OUT / "arrays-compressed.npz", x=np.ones(100, dtype="f8"))

# Object arrays: the data section is a pickle, so numpy.load needs allow_pickle=True.
np.save(OUT / "object.npy", np.array([{"a": 1}, [2, 3]], dtype=object), allow_pickle=True)
obj = np.empty(2, dtype=object)
obj[0] = {"k": "v"}
obj[1] = (1, 2)
np.savez(OUT / "object.npz", obj=obj)

# A legitimate file whose header exceeds numpy's own max_header_size of 10000,
# so numpy.load refuses it by default.
wide = np.zeros(1, dtype=[(f"field_{i:03d}", "<f4") for i in range(2000)])
np.save(OUT / "big-header.npy", wide)

print("\n".join(sorted(p.name for p in OUT.iterdir() if p.suffix in (".npy", ".npz"))))
