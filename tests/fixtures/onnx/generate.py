"""Regenerate the ONNX fixtures with the real onnx package.

Not run by the test suite: CI has no onnx, which is why the fixtures are
committed. Requires `pip install onnx`.

    python generate.py

Nothing here is loaded by the scanner; the external_data paths point at files
that do not exist, and the scanner never opens them.
"""
from pathlib import Path

import numpy as np
from onnx import TensorProto, helper, numpy_helper
from onnx.external_data_helper import set_external_data

OUT = Path(__file__).resolve().parent


def dense_model(path, location=None):
    w = numpy_helper.from_array(np.ones((2, 2), dtype=np.float32), name="W")
    if location is not None:
        set_external_data(w, location=location)
        w.ClearField("raw_data")
        w.data_location = TensorProto.EXTERNAL
    node = helper.make_node("MatMul", ["X", "W"], ["Y"])
    graph = helper.make_graph(
        [node], "g",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 2])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 2])],
        initializer=[w],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 20)])
    (OUT / path).write_bytes(model.SerializeToString())


dense_model("clean.onnx")
dense_model("extdata-ok.onnx", location="weights.bin")
dense_model("extdata-parent.onnx", location="../../../etc/passwd")
dense_model("extdata-absolute.onnx", location="/etc/passwd")
dense_model("extdata-subdir-escape.onnx", location="sub/../../secret.bin")

custom = helper.make_node("RunPython", ["X"], ["Y"], domain="ai.evil")
graph = helper.make_graph(
    [custom], "g",
    [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1])],
    [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])],
)
model = helper.make_model(
    graph, opset_imports=[helper.make_opsetid("", 20), helper.make_opsetid("ai.evil", 1)])
(OUT / "custom-domain.onnx").write_bytes(model.SerializeToString())

print("\n".join(sorted(p.name for p in OUT.glob("*.onnx"))))
