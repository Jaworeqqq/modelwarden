# Third-party notices

## picklescan

`src/modelwarden/scanners/supply_chain/unsafe_globals.py` contains verbatim copies
of the `_unsafe_globals` and `_safe_globals` lists from
[picklescan](https://github.com/mmaitre314/picklescan) (`src/picklescan/scanner.py`,
snapshot taken 2026-09-10), used under the following license:

```
MIT License

Copyright (c) 2022 Matthieu Maitre

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## fickling (reference only)

`tests/test_gadgets.py` measures detection against callables named in the bypass
suite of [fickling](https://github.com/trailofbits/fickling) (Trail of Bits,
LGPL-3.0), alongside those in picklescan's fixture generator.

**No fickling code or data is included, and none may be**: LGPL-3.0 is not
compatible with this project's MIT licence. What was taken is the list of module and
callable names — `runpy`, `_operator.methodcaller`, `pydoc`, `ctypes` and the rest —
each of which corresponds to a published security advisory, and the shape of the
frame-boundary case reported upstream as python/cpython#154848. The pickles that
exercise them are assembled from raw opcodes by this project's own `builders.py`.

## modelscan (reference only)

The `unsafe_globals` settings of [modelscan](https://github.com/protectai/modelscan)
(Protect AI, Apache License 2.0) were used as a cross-check of the list above. No
modelscan code or data is included: every modelscan entry is already covered by
picklescan's list, except `builtins.__import__`, which modelwarden lists as its own
addition.
