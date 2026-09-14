"""HDF5: legacy Keras .h5 models and the model.weights.h5 inside .keras archives.

A minimal read-only walker over superblocks, object headers, symbol-table groups,
link messages and heaps. libhdf5 (through h5py) is deliberately not used. Several
Keras CVEs are libhdf5 features doing their job (external links, external
storage, virtual datasets) or libhdf5 allocating what a file declares (shape
bombs), and a C parser inside the scanner would face the same files it is meant
to judge. Nothing found is ever resolved: external files are named, not opened.
"""
from __future__ import annotations

import math
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from modelwarden.core.detect import Format
from modelwarden.core.findings import Finding, Location, Rule, Severity
from modelwarden.scanners.supply_chain import keras
from modelwarden.scanners.supply_chain.pickle import ATLAS, OWASP

EXTERNAL_LINK = Rule(
    "MW-SC-060",
    "HDF5 external link",
    "A link points into another file. Loaders that follow links read whatever file the "
    "path names; Keras weight loading did (CVE-2026-9335).",
    Severity.HIGH, ATLAS, OWASP,
)
EXTERNAL_STORAGE = Rule(
    "MW-SC-061",
    "HDF5 dataset stored in external files",
    "The dataset's raw data lives in files named by path, which are read when the "
    "dataset is read (CVE-2026-1669).",
    Severity.HIGH, ATLAS, OWASP,
)
VIRTUAL_DATASET = Rule(
    "MW-SC-062",
    "HDF5 virtual dataset",
    "The dataset maps data from other files, which are read when the dataset is read "
    "(CVE-2026-12480).",
    Severity.HIGH, ATLAS, OWASP,
)
SIZE_BOMB = Rule(
    "MW-SC-063",
    "HDF5 dataset declares an implausible size",
    "Shape times element size is far larger than the file. Loaders that allocate the "
    "declared size exhaust memory (CVE-2026-0897, CVE-2026-12570).",
    Severity.MEDIUM, ("AML.T0029",), OWASP,
)
MALFORMED = Rule(
    "MW-SC-064",
    "Malformed HDF5 structure",
    "An address points outside the file, a signature is wrong, or a structure is "
    "truncated or cyclic. The walk stops there; what was found before is still reported.",
    Severity.MEDIUM, ATLAS, OWASP,
)
NOT_ANALYSED = Rule(
    "MW-SC-065",
    "HDF5 structure not analysed",
    "Part of the file uses structures this walker does not read: a filtered fractal heap, "
    "addresses wider than 8 bytes, user-defined link types. Links and attributes stored "
    "there were not checked.",
    Severity.MEDIUM, ATLAS, OWASP,
)
USER_BLOCK = Rule(
    "MW-SC-066",
    "Data before the HDF5 superblock",
    "The file begins with a user block: bytes that HDF5 itself skips and no HDF5 tool "
    "will show. Anything can sit there, including a script, and the file still loads.",
    Severity.LOW, ATLAS, OWASP,
)
HDF5_RULES = (
    EXTERNAL_LINK, EXTERNAL_STORAGE, VIRTUAL_DATASET, SIZE_BOMB, MALFORMED, NOT_ANALYSED,
    USER_BLOCK,
)

# A user block is a power-of-two number of bytes, at least 512, before the superblock.
# There is deliberately no cap on the user-block search below. One used to sit here at
# 1 << 24, and a user block one doubling past it hid the entire file from detection: the
# superblock was never found, no format matched, and a 33 MB HDF5 model was answered
# "matches no supported format". The search probes powers of two, so covering a terabyte
# costs about thirty seeks — the limit bought nothing and paid for it with a blind spot.

MAX_OBJECTS = 1_000_000
MAX_BLOCKS = 100_000          # continuation blocks per header, B-tree nodes per group
# A version 2 B-tree of this node size holds more records at depth 4 than any file can
# contain; a deeper one is corrupt or crafted, and recursion should not follow it.
MAX_BTREE_DEPTH = 8
MAX_READ = 256 * 1024 * 1024  # a single structure larger than this is not plausible
# A declared size is a bomb when it is both large in absolute terms and far larger than the file.
BOMB_MIN_BYTES = 1 << 30
BOMB_FILE_FACTOR = 1000

_UNDEFINED = 0xFFFF_FFFF_FFFF_FFFF
# Header message types (HDF5 file format specification, section IV.A.2).
_DATASPACE, _LINK_INFO, _DATATYPE, _LINK = 0x01, 0x02, 0x03, 0x06
_EXTERNAL_FILES, _LAYOUT, _ATTRIBUTE = 0x07, 0x08, 0x0C
_CONTINUATION, _SYMBOL_TABLE, _ATTRIBUTE_INFO = 0x10, 0x11, 0x15
_LINK_HARD, _LINK_SOFT, _LINK_EXTERNAL = 0, 1, 64
# Fractal heap header fields, and the version 2 B-tree that indexes link names.
# The offsets were read off files written by h5py rather than taken on trust.
_FRHP_SIZE = 142
_FRHP_ID_SIZE, _FRHP_FILTER_LEN, _FRHP_FLAGS, _FRHP_MAX_MANAGED = 5, 7, 9, 10
_FRHP_START_BLOCK, _FRHP_MAX_DBLOCK = 112, 120
_FRHP_LOG2_HEAP, _FRHP_ROOT_BLOCK, _FRHP_ROWS = 128, 132, 140
_FRHP_TABLE_WIDTH = 110
_BTHD_SIZE, _BTHD_NODE_SIZE = 34, 6
_BTREE_LINK_NAMES, _BTREE_ATTR_NAMES = 5, 8
_HEAP_ID_MANAGED = 0
_LAYOUT_VIRTUAL = 3
_CLASS_STRING, _CLASS_VLEN = 3, 9
KERAS_CONFIG_ATTRIBUTE = "model_config"


class _Stop(Exception):
    def __init__(self, rule: Rule, offset: int | None, message: str):
        super().__init__(message)
        self.rule, self.offset = rule, offset


class HDF5Scanner:
    name = "hdf5"
    formats = frozenset({Format.HDF5})
    rules = (*HDF5_RULES, *keras.KERAS_RULES)

    def scan(self, path: Path, display: str) -> Iterator[Finding]:
        with path.open("rb") as fh:
            yield from scan_hdf5(fh, path.stat().st_size, display)


def scan_hdf5(
    fh: BinaryIO, size: int, display: str, member: str | None = None
) -> Iterator[Finding]:
    """Walk an HDF5 file read from a seekable stream of `size` bytes."""
    walker = _Walker(fh, size, display, member)
    try:
        walker.walk()
    except _Stop as stop:
        walker.report(stop.rule, str(stop), stop.offset)
    except (struct.error, IndexError) as exc:
        walker.report(MALFORMED, f"truncated structure ({exc})", None)
    yield from walker.findings


class _Walker:
    def __init__(self, fh: BinaryIO, size: int, display: str, member: str | None):
        self.fh, self.size, self.display, self.member = fh, size, display, member
        self.base = 0
        self.findings: list[Finding] = []

    def report(self, rule: Rule, message: str, offset: int | None,
               severity: Severity | None = None, evidence: str = "") -> None:
        where = Location(self.display, self.member, offset)
        severity = severity or rule.default_severity
        self.findings.append(Finding(rule, severity, message, where, evidence))

    def read(self, address: int, n: int) -> bytes:
        if n < 0 or n > MAX_READ:
            raise _Stop(MALFORMED, address, f"structure of {n} bytes is not plausible")
        if address < 0 or address + n > self.size:
            raise _Stop(MALFORMED, address, f"{n} bytes at {address:#x} lie outside the "
                                            f"{self.size}-byte file")
        self.fh.seek(address)
        data = self.fh.read(n)
        if len(data) != n:
            raise _Stop(MALFORMED, address, "file ends inside a structure")
        return data

    def addr(self, relative: int) -> int:
        return relative + self.base

    # --- file structure -------------------------------------------------------

    def walk(self) -> None:
        seen: set[int] = set()
        queue = [(self._superblock(), "/")]
        while queue:
            address, path = queue.pop()
            if address in seen:
                continue  # hard links may form cycles, which is legal
            if len(seen) >= MAX_OBJECTS:
                raise _Stop(NOT_ANALYSED, None, f"more than {MAX_OBJECTS} objects")
            seen.add(address)
            self._object(address, path, queue)

    def _superblock(self) -> int:
        start = superblock_offset(self.fh, self.size)
        if start is None:
            raise _Stop(MALFORMED, 0, "no HDF5 superblock in this file")
        if start:
            preview = _text(self.read(0, min(48, start))).replace("\n", " ").strip()
            self.report(USER_BLOCK, f"{start} bytes precede the superblock: {preview[:40]!r}", 0,
                        evidence=preview[:40])

        head = self.read(start, 16)
        version = head[8]
        if version in (0, 1):
            self._require_8_byte_fields(head[13], head[14])
            extra = 4 if version == 1 else 0  # v1 adds the indexed storage K value
            (self.base,) = struct.unpack("<Q", self.read(start + 24 + extra, 8))
            # Root group symbol table entry follows four addresses; its object header
            # address is the entry's second field.
            (root,) = struct.unpack("<Q", self.read(start + 64 + extra, 8))
        elif version in (2, 3):
            self._require_8_byte_fields(head[9], head[10])
            (self.base,) = struct.unpack("<Q", self.read(start + 12, 8))
            (root,) = struct.unpack("<Q", self.read(start + 36, 8))
        else:
            raise _Stop(NOT_ANALYSED, start + 8,
                        f"superblock version {version} is not supported")
        return self.addr(root)

    @staticmethod
    def _require_8_byte_fields(offset_size: int, length_size: int) -> None:
        if (offset_size, length_size) != (8, 8):
            raise _Stop(NOT_ANALYSED, 13, f"file uses {offset_size}-byte addresses and "
                                          f"{length_size}-byte lengths; only 8 is supported")

    def _object(self, address: int, path: str, queue: list[tuple[int, str]]) -> None:
        messages = self._messages(address)
        for mtype, body, offset in messages:
            if mtype == _SYMBOL_TABLE:
                self._symbol_table(body, path, queue)
            elif mtype == _LINK:
                self._link(body, offset, path, queue)
            elif mtype in (_LINK_INFO, _ATTRIBUTE_INFO):
                self._dense_storage(mtype, body, offset, path, queue)
            elif mtype == _ATTRIBUTE:
                self._attribute(body, offset, path)
            elif mtype == _EXTERNAL_FILES:
                self._external_files(body, offset, path)
        if any(mtype == _LAYOUT for mtype, _, _ in messages):
            self._dataset(messages, path)

    # --- object headers -------------------------------------------------------

    def _messages(self, address: int) -> list[tuple[int, bytes, int]]:
        prefix = self.read(address, 4)
        if prefix == b"OHDR":
            return self._messages_v2(address)
        if prefix[0] == 1:
            head = self.read(address, 16)
            (messages,) = struct.unpack_from("<H", head, 2)
            (references,) = struct.unpack_from("<I", head, 4)
            # A stray 0x01 anywhere in the file used to be enough to be read as a
            # version 1 object header, so an address off by eight bytes landed on one
            # and the walk continued into nothing without a word. A real header has a
            # zero reserved byte and exactly one reference: measured across all 26
            # version 1 headers in the corpus, every one does.
            if head[1] or references != 1 or not messages:
                raise _Stop(MALFORMED, address,
                            "not a version 1 object header: reserved byte "
                            f"{head[1]}, {references} reference(s), {messages} message(s)")
            (size,) = struct.unpack_from("<I", head, 8)
            return self._blocks([(address + 16, size)], header=8, version=1)
        raise _Stop(MALFORMED, address, "no object header at this address")

    def _messages_v2(self, address: int) -> list[tuple[int, bytes, int]]:
        version, flags = self.read(address + 4, 2)
        if version != 2:
            raise _Stop(MALFORMED, address, f"object header version {version}")
        pos = address + 6
        if flags & 0x20:
            pos += 16  # access, modification, change and birth times
        if flags & 0x10:
            pos += 4   # attribute storage phase change values
        width = 1 << (flags & 0x03)
        chunk0 = int.from_bytes(self.read(pos, width), "little")
        header = 6 if flags & 0x04 else 4  # creation order field present
        return self._blocks([(pos + width, chunk0)], header=header, version=2)

    def _blocks(self, blocks: list[tuple[int, int]], header: int, version: int
                ) -> list[tuple[int, bytes, int]]:
        messages: list[tuple[int, bytes, int]] = []
        count = 0
        while blocks:
            start, length = blocks.pop(0)
            count += 1
            if count > MAX_BLOCKS:
                raise _Stop(MALFORMED, start, "too many object header continuation blocks")
            data = self.read(start, length)
            pos = 0
            while pos + header <= len(data):
                fmt = "<HH" if version == 1 else "<BH"
                mtype, msize = struct.unpack_from(fmt, data, pos)
                body = pos + header
                if body + msize > len(data):
                    raise _Stop(MALFORMED, start + pos, "header message runs past its block")
                payload = data[body:body + msize]
                if mtype == _CONTINUATION:
                    target, span = struct.unpack_from("<QQ", payload)
                    target = self.addr(target)
                    if version == 2:
                        if self.read(target, 4) != b"OCHK":
                            raise _Stop(MALFORMED, target, "continuation block without OCHK")
                        blocks.append((target + 4, span - 8))  # signature and checksum
                    else:
                        blocks.append((target, span))
                elif mtype:
                    messages.append((mtype, payload, start + body))
                pos = body + msize
        return messages

    # --- groups and links -----------------------------------------------------

    def _symbol_table(self, body: bytes, path: str, queue: list[tuple[int, str]]) -> None:
        btree, heap = (self.addr(a) for a in struct.unpack_from("<QQ", body))
        names = self._local_heap(heap)
        stack, visited, delivered = [btree], set(), 0
        while stack:
            node = stack.pop()
            if node in visited or len(visited) >= MAX_BLOCKS:
                raise _Stop(MALFORMED, node, "group B-tree is cyclic or too large")
            visited.add(node)
            head = self.read(node, 24)
            if head[:4] != b"TREE" or head[4] != 0:
                raise _Stop(MALFORMED, node, "not a group B-tree node")
            level, (entries,) = head[5], struct.unpack_from("<H", head, 6)
            keys_and_children = self.read(node + 24, entries * 16 + 8)
            children = [self.addr(struct.unpack_from("<Q", keys_and_children, 8 + 16 * i)[0])
                        for i in range(entries)]
            if level:
                stack.extend(children)
            else:
                for child in children:
                    delivered += 1
                    self._symbol_node(child, names, path, queue)

        # A B-tree that delivers nothing for a group whose heap still holds a name is
        # what one flipped bit produces: the count goes to zero, the traversal ends
        # quietly, and the file keeps its contents. An empty group is ordinary and has
        # an empty heap with it, so the two conditions together separate them —
        # measured across 15 groups in the corpus, none is flagged.
        if not delivered and _heap_names(names):
            self.report(MALFORMED,
                        f"{path} lists no children but its heap names "
                        f"{', '.join(_heap_names(names)[:3])}", btree)

    def _symbol_node(self, address: int, names: bytes, path: str,
                     queue: list[tuple[int, str]]) -> None:
        head = self.read(address, 8)
        if head[:4] != b"SNOD":
            raise _Stop(MALFORMED, address, "not a symbol table node")
        (count,) = struct.unpack_from("<H", head, 6)
        entries = self.read(address + 8, count * 40)
        for i in range(count):
            name_offset, target, cache_type = struct.unpack_from("<QQI", entries, i * 40)
            if cache_type == 2:
                continue  # soft link: a path inside this file
            queue.append((self.addr(target), _join(path, _heap_string(names, name_offset))))

    def _link(self, body: bytes, offset: int, path: str, queue: list[tuple[int, str]]) -> None:
        flags, pos = body[1], 2
        link_type = _LINK_HARD
        if flags & 0x08:
            link_type, pos = body[pos], pos + 1
        if flags & 0x04:
            pos += 8  # creation order
        if flags & 0x10:
            pos += 1  # name character set
        width = 1 << (flags & 0x03)
        name_length = int.from_bytes(body[pos:pos + width], "little")
        pos += width
        where = _join(path, body[pos:pos + name_length].decode("utf-8", "replace"))
        pos += name_length

        if link_type == _LINK_HARD:
            (target,) = struct.unpack_from("<Q", body, pos)
            queue.append((self.addr(target), where))
        elif link_type == _LINK_EXTERNAL:
            (length,) = struct.unpack_from("<H", body, pos)
            info = body[pos + 3:pos + 2 + length]  # skip the length and the version/flags byte
            file_name, _, rest = info.partition(b"\0")
            target = f"{_text(file_name)}:{_text(rest.partition(b'\0')[0])}"
            self.report(EXTERNAL_LINK, f"{where} links to {target}", offset, evidence=target)
        elif link_type != _LINK_SOFT:
            self.report(NOT_ANALYSED, f"{where} uses user-defined link type {link_type}", offset)

    def _dense_storage(self, mtype: int, body: bytes, offset: int, path: str,
                       queue: list[tuple[int, str]]) -> None:
        flags = body[1]
        if mtype == _LINK_INFO:
            pos = 2 + (8 if flags & 0x01 else 0)  # maximum creation index
            what, btree_type, id_first = "links", _BTREE_LINK_NAMES, False
        else:
            pos = 2 + (2 if flags & 0x01 else 0)
            what, btree_type, id_first = "attributes", _BTREE_ATTR_NAMES, True
        heap, names = struct.unpack_from("<QQ", body, pos)
        if heap == _UNDEFINED:
            return

        objects = None
        if names != _UNDEFINED:
            objects = self._heap_objects(heap, names, btree_type, id_first)
        if objects is None:
            self.report(NOT_ANALYSED,
                        f"{path} keeps its {what} in dense storage, not checked", offset)
            return
        for data, at in objects:
            if mtype == _LINK_INFO:
                self._link(data, at, path, queue)
            else:
                self._attribute(data, at, path)

    def _heap_objects(self, heap: int, names: int, btree_type: int, id_first: bool
                      ) -> list[tuple[bytes, int]] | None:
        """Objects of a fractal heap, found through the version 2 B-tree that names them.

        None whenever a shape is not read, so the caller reports that nothing was
        checked instead of passing over the contents in silence.
        """
        header = self.read(self.addr(heap), _FRHP_SIZE)
        if header[:4] != b"FRHP":
            raise _Stop(MALFORMED, self.addr(heap), "not a fractal heap")
        (id_size,) = struct.unpack_from("<H", header, _FRHP_ID_SIZE)
        (filter_len,) = struct.unpack_from("<H", header, _FRHP_FILTER_LEN)
        (max_managed,) = struct.unpack_from("<I", header, _FRHP_MAX_MANAGED)
        (table_width,) = struct.unpack_from("<H", header, _FRHP_TABLE_WIDTH)
        start_block, max_dblock = struct.unpack_from("<QQ", header, _FRHP_START_BLOCK)
        (log2_heap,) = struct.unpack_from("<H", header, _FRHP_LOG2_HEAP)
        (root_block,) = struct.unpack_from("<Q", header, _FRHP_ROOT_BLOCK)
        (rows,) = struct.unpack_from("<H", header, _FRHP_ROWS)
        # A filtered heap puts a stored size and a filter mask beside every block address,
        # so the table no longer steps eight bytes at a time. Left unread rather than
        # misread: the difference between the two is a scanner that reports confident
        # nonsense and one that says it did not look.
        if root_block == _UNDEFINED or not start_block or not table_width or filter_len:
            return None

        offset_size = _bytes_for_bits(log2_heap)
        length_size = _bytes_for_bits(min(max_dblock, max_managed).bit_length())
        if 1 + offset_size + length_size > id_size:
            return None
        table = self._doubling_table(root_block, rows, table_width, start_block, offset_size)
        heap_ids = self._name_index(names, id_size, btree_type, id_first)
        if table is None or heap_ids is None:
            return None

        # Resolve every record before reading any, so an unsupported one cannot leave
        # half the objects examined and the other half silently dropped.
        placed = []
        for heap_id in heap_ids:
            if (heap_id[0] >> 4) & 3 != _HEAP_ID_MANAGED:
                return None
            start = int.from_bytes(heap_id[1:1 + offset_size], "little")
            end = 1 + offset_size + length_size
            length = int.from_bytes(heap_id[1 + offset_size:end], "little")
            where = _locate(table, start, length)
            if where is None:
                return None
            placed.append((where, length))
        return [(self.read(at, length), at) for at, length in placed]

    def _doubling_table(self, root_block: int, rows: int, table_width: int,
                        start_block: int, offset_size: int
                        ) -> list[tuple[int, int, int]] | None:
        """Which direct block holds each logical heap offset, as (offset, size, address).

        A small heap is one direct block at the root. A larger one puts an indirect
        block there listing the table: rows 0 and 1 hold blocks of the starting size,
        and every row after that doubles it.
        """
        root = self.addr(root_block)
        if not rows:
            if self.read(root, 4) != b"FHDB":
                return None
            return [(0, start_block, root)]

        entries = rows * table_width
        if entries > MAX_BLOCKS:
            return None
        # Signature, version, the address of the heap header, then this block's own
        # offset, which is as wide as the heap's addresses rather than 8 bytes.
        base = 4 + 1 + 8 + offset_size
        block = self.read(root, base + entries * 8 + 4)
        if block[:4] != b"FHIB":
            return None
        table, logical = [], 0
        for row in range(rows):
            size = start_block if row < 2 else start_block * (1 << (row - 1))
            for column in range(table_width):
                (address,) = struct.unpack_from("<Q", block,
                                                base + (row * table_width + column) * 8)
                table.append((logical, size,
                              _UNDEFINED if address == _UNDEFINED else self.addr(address)))
                logical += size
        return table

    def _name_index(self, address: int, id_size: int, btree_type: int, id_first: bool
                    ) -> list[bytes] | None:
        """Heap IDs from a version 2 B-tree of names, at any indexed depth.

        A link record opens with a 4-byte hash of the name and an attribute record opens
        with the heap ID itself. That difference was read off files written by h5py, not
        taken on trust: reading an attribute tree with the link layout returns bytes that
        decode into plausible nonsense rather than failing.
        """
        header = self.read(self.addr(address), _BTHD_SIZE)
        if header[:4] != b"BTHD" or header[5] != btree_type:
            return None
        (node_size,) = struct.unpack_from("<I", header, _BTHD_NODE_SIZE)
        (record_size,) = struct.unpack_from("<H", header, 10)
        (depth,) = struct.unpack_from("<H", header, 12)
        (root,) = struct.unpack_from("<Q", header, 16)
        (count,) = struct.unpack_from("<H", header, 24)
        skip = 0 if id_first else 4
        if root == _UNDEFINED or record_size < skip + id_size or node_size < 10 + record_size:
            return None
        if depth > MAX_BTREE_DEPTH:
            return None
        geometry = _btree_geometry(node_size, record_size, depth)
        if geometry is None:
            return None

        ids: list[bytes] = []

        def records(node: bytes, n: int) -> list[bytes]:
            return [node[6 + i * record_size + skip:6 + i * record_size + skip + id_size]
                    for i in range(n)]

        def visit(address: int, n: int, level: int) -> bool:
            node = self.read(self.addr(address), node_size)
            if level == 0:
                if node[:4] != b"BTLF":
                    return False
                ids.extend(records(node, n))
                return True
            if node[:4] != b"BTIN":
                return False
            width, count_size = geometry[level]
            pointer = 6 + n * record_size
            if pointer + (n + 1) * width + 4 > node_size:
                return False
            # In-order: every child, with the node's own records between them, so the
            # heap IDs come back in the order the index holds them.
            own = records(node, n)
            for i in range(n + 1):
                at = pointer + i * width
                (child,) = struct.unpack_from("<Q", node, at)
                child_n = int.from_bytes(node[at + 8:at + 8 + count_size], "little")
                if child_n == 0 or len(ids) > MAX_OBJECTS:
                    return False
                if not visit(child, child_n, level - 1):
                    return False
                if i < n:
                    ids.append(own[i])
            return True

        return ids if visit(root, count, depth) else None

    # --- attributes -----------------------------------------------------------

    def _attribute(self, body: bytes, offset: int, path: str) -> None:
        version = body[0]
        name_size, type_size, space_size = struct.unpack_from("<HHH", body, 2)
        if version == 1:
            pos, pad = 8, 8
        elif version in (2, 3):
            pos, pad = (8 if version == 2 else 9), 1
        else:
            raise _Stop(MALFORMED, offset, f"attribute message version {version}")
        name = body[pos:pos + name_size].rstrip(b"\0").decode("utf-8", "replace")
        if path != "/" or name != KERAS_CONFIG_ATTRIBUTE:
            return
        pos += _padded(name_size, pad)
        datatype = body[pos:pos + type_size]
        pos += _padded(type_size, pad) + _padded(space_size, pad)

        text = self._string_value(datatype, body[pos:])
        if text is None:
            self.report(MALFORMED, f"{KERAS_CONFIG_ATTRIBUTE} is not a string attribute", offset)
            return
        from modelwarden.scanners.supply_chain.archive import embedded_blob

        label = f"{self.member}#/{name}" if self.member else f"/{name}"
        self.findings.extend(keras.scan_config(text, self.display, label, embedded_blob))

    def _string_value(self, datatype: bytes, value: bytes) -> bytes | None:
        cls = datatype[0] & 0x0F
        if cls == _CLASS_STRING:
            (size,) = struct.unpack_from("<I", datatype, 4)
            return value[:size].rstrip(b"\0")
        if cls == _CLASS_VLEN and datatype[1] & 0x0F == 1:  # variable-length string
            length, collection, index = struct.unpack_from("<IQI", value)
            return self._global_heap_object(self.addr(collection), index)[:length]
        return None

    # --- datasets -------------------------------------------------------------

    def _external_files(self, body: bytes, offset: int, path: str) -> None:
        # version, 3 reserved bytes, allocated slots, used slots, local heap address
        used, heap = struct.unpack_from("<HQ", body, 6)
        names = self._local_heap(self.addr(heap))
        files = [_heap_string(names, struct.unpack_from("<Q", body, 16 + 24 * i)[0])
                 for i in range(used)]
        self.report(EXTERNAL_STORAGE, f"{path} stores its data in {', '.join(files)}", offset,
                    evidence=files[0] if files else "")

    def _dataset(self, messages: list[tuple[int, bytes, int]], path: str) -> None:
        first: dict[int, tuple[bytes, int]] = {}
        for mtype, body, offset in messages:
            first.setdefault(mtype, (body, offset))

        layout, layout_offset = first[_LAYOUT]
        layout_class = layout[2] if layout[0] in (1, 2) else layout[1]
        if layout_class == _LAYOUT_VIRTUAL:
            collection, index = struct.unpack_from("<QI", layout, 2)
            mapping = self._global_heap_object(self.addr(collection), index)
            (count,) = struct.unpack_from("<Q", mapping, 1)
            source = _text(mapping[9:].partition(b"\0")[0])
            self.report(VIRTUAL_DATASET, f"{path} maps data from {count} source(s), first "
                                         f"{source!r}", layout_offset, evidence=source)

        if _DATASPACE in first and _DATATYPE in first:
            space, space_offset = first[_DATASPACE]
            dims = _dims(space, space_offset)
            (itemsize,) = struct.unpack_from("<I", first[_DATATYPE][0], 4)
            declared = math.prod(dims) * itemsize if dims else 0
            if declared >= 2**64:
                self.report(SIZE_BOMB, f"{path} declares {dims} x {itemsize} bytes, overflowing "
                                       "64 bits", space_offset, severity=Severity.HIGH)
            elif declared > max(BOMB_MIN_BYTES, BOMB_FILE_FACTOR * self.size):
                self.report(SIZE_BOMB, f"{path} declares {declared} bytes ({dims} x {itemsize}) "
                                       f"in a {self.size}-byte file", space_offset)

    # --- heaps ----------------------------------------------------------------

    def _local_heap(self, address: int) -> bytes:
        head = self.read(address, 32)
        if head[:4] != b"HEAP":
            raise _Stop(MALFORMED, address, "not a local heap")
        size, _free_list, data = struct.unpack_from("<QQQ", head, 8)
        return self.read(self.addr(data), size)

    def _global_heap_object(self, address: int, index: int) -> bytes:
        head = self.read(address, 16)
        if head[:4] != b"GCOL":
            raise _Stop(MALFORMED, address, "not a global heap collection")
        (size,) = struct.unpack_from("<Q", head, 8)
        data = self.read(address + 16, size - 16)
        pos = 0
        while pos + 16 <= len(data):
            object_index, _refs, _reserved, object_size = struct.unpack_from("<HHIQ", data, pos)
            if object_index == 0:
                break  # free space marks the end of the collection
            if object_index == index:
                return data[pos + 16:pos + 16 + object_size]
            pos += 16 + _padded(object_size, 8)
        raise _Stop(MALFORMED, address, f"global heap object {index} not found")


def superblock_offset(fh: BinaryIO, size: int) -> int | None:
    """Where the superblock starts: offset 0, or after a user block of 512, 1024, ... bytes.

    libhdf5 reads such a file without complaint, and whatever precedes the superblock is
    invisible to every HDF5 tool, so a scanner that only looks at offset 0 sees nothing.
    """
    from modelwarden.core.detect import HDF5_MAGIC

    offset = 0
    while offset + len(HDF5_MAGIC) <= size:
        fh.seek(offset)
        if fh.read(len(HDF5_MAGIC)) == HDF5_MAGIC:
            return offset
        offset = 512 if offset == 0 else offset * 2
    return None


def _dims(body: bytes, offset: int) -> list[int]:
    version, rank = body[0], body[1]
    if version == 1:
        start = 8
    elif version == 2:
        if body[3] == 2:
            return []  # null dataspace: no elements
        start = 4
    else:
        raise _Stop(MALFORMED, offset, f"dataspace message version {version}")
    return list(struct.unpack_from(f"<{rank}Q", body, start))


def _locate(table: list[tuple[int, int, int]], start: int, length: int) -> int | None:
    """The file address of a heap object, or None when it does not sit in one block.

    Offsets count from the first byte of the block, its header included. Reading them
    as counting from the end of the header parses zero records out of thirty-three.
    """
    if length == 0:
        return None
    for logical, size, address in table:
        if logical <= start < logical + size:
            if address == _UNDEFINED or start - logical + length > size:
                return None
            return address + (start - logical)
    return None


def _btree_geometry(node_size: int, record_size: int, depth: int
                    ) -> list[tuple[int, int]] | None:
    """Child-pointer width and record-count width for each level of a version 2 B-tree.

    A pointer holds the child's address, how many records that child holds, and — above
    level one — how many the whole subtree under it holds. Each count is as wide as the
    largest value it could take, which depends on how many records fit in a node, so the
    geometry has to be built up a level at a time instead of read from a field.

    Solved against files written by h5py rather than taken from the specification:
    512-byte nodes of 17-byte records give a 9-byte pointer at level one and 11 at level
    two, and the subtree totals then add up to the record count in the B-tree header —
    268 + 243 + 1 for 512 attributes, 372 + 392 + 258 + 2 for 1024.
    """
    per_leaf = (node_size - 10) // record_size
    if per_leaf <= 0:
        return None
    geometry = [(0, 0)]  # a leaf carries records only, no child pointers
    in_node = in_subtree = per_leaf
    for level in range(1, depth + 1):
        count_size = _bytes_for_bits(in_node.bit_length())
        total_size = _bytes_for_bits(in_subtree.bit_length()) if level > 1 else 0
        width = 8 + count_size + total_size
        geometry.append((width, count_size))
        fits = (node_size - 10 - width) // (record_size + width)
        if fits <= 0:
            return None
        in_node, in_subtree = fits, fits + (fits + 1) * in_subtree
    return geometry


def _bytes_for_bits(bits: int) -> int:
    return bits // 8 + min(bits % 8, 1)


def _padded(size: int, multiple: int) -> int:
    return -(-size // multiple) * multiple


def _join(path: str, name: str) -> str:
    return f"{path.rstrip('/')}/{name}"


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def _heap_names(heap: bytes) -> list[str]:
    """Whether a group's local heap holds anything that looks like a name.

    A local heap is NUL-separated strings with padding around them, so this filter is
    deliberately loose. It answers one question — does this group name something? —
    and is not an attempt to enumerate children exactly. The predicate is the one the
    false-positive measurement used; tightening it would invalidate that calibration.
    """
    return [raw.decode("utf-8", "replace")
            for raw in heap.split(b"\x00") if len(raw) > 1 and raw.isascii()]


def _heap_string(heap: bytes, offset: int) -> str:
    end = heap.find(b"\0", offset)
    return _text(heap[offset:end]) if 0 <= offset < len(heap) and end >= 0 else "?"
