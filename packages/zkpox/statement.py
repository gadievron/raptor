"""Fixed-width SP1 public statement and hiding witness commitment.

The statement binds a curated source target, selected canary predicate and
private witness. It does not prove correctness of an encrypted delivery.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct

VERSION = 2
PUBLIC_LEN = 88
MAX_WITNESS = 1024 * 1024
SYSTEM = "sp1-groth16/6.5.0"
_DOMAIN = b"raptor-zkpox-witness-v2\0"
_TARGETS = {1: "01-stack-bof.c", 2: "02-off-by-one.c", 3: "03-libxml2-cve-2017-9047.c"}


def source_hash(target: int) -> bytes:
    if type(target) is not int or target not in _TARGETS:
        raise ValueError("unsupported curated target")
    return hashlib.sha256((Path(__file__).parent / "native" / "targets" / _TARGETS[target]).read_bytes()).digest()


def commitment(target: int, gadget: int, salt: bytes, witness: bytes) -> bytes:
    source_hash(target)
    if type(gadget) is not int or gadget not in (1, 2):
        raise ValueError("unsupported gadget selector")
    if type(salt) is not bytes or len(salt) != 32:
        raise ValueError("salt must contain exactly 32 bytes")
    if type(witness) is not bytes or len(witness) > MAX_WITNESS:
        raise ValueError("unsupported witness size/type")
    return hashlib.sha256(_DOMAIN + struct.pack("<II", target, gadget) + salt + witness).digest()


@dataclass(frozen=True)
class Statement:
    target_id: int
    gadget_id: int
    flags: int
    oob_count: int
    oob_first_offset: int
    witness_commitment: bytes
    target_source_hash: bytes

    def encode(self) -> bytes:
        for value in (self.target_id, self.gadget_id, self.flags, self.oob_count, self.oob_first_offset):
            if type(value) is not int:
                raise ValueError("statement words must be integers")
        for value in (self.witness_commitment, self.target_source_hash):
            if type(value) is not bytes or len(value) != 32:
                raise ValueError("statement digests must contain 32 bytes")
        return struct.pack("<IIIIIi32s32s", VERSION, self.target_id, self.gadget_id,
                           self.flags, self.oob_count, self.oob_first_offset,
                           self.witness_commitment, self.target_source_hash)

    @classmethod
    def decode(cls, data: bytes) -> "Statement":
        if type(data) is not bytes or len(data) != PUBLIC_LEN:
            raise ValueError("incorrect public statement length")
        version, *fields = struct.unpack("<IIIIIi32s32s", data)
        if version != VERSION:
            raise ValueError("unsupported statement version")
        return cls(*fields)

    def validate(self) -> None:
        self.encode()
        if self.target_source_hash != source_hash(self.target_id):
            raise ValueError("target source hash mismatch")
        if self.flags & ~3 or self.gadget_id not in (1, 2):
            raise ValueError("unsupported verdict flags/gadget")
        if not self.flags & (1 << (self.gadget_id - 1)):
            raise ValueError("execution did not demonstrate the claimed violation")
        buf_size = 32 if self.target_id == 3 else 16
        if self.flags & 2:
            if not 1 <= self.oob_count <= MAX_WITNESS + 64 or not -16 <= self.oob_first_offset < MAX_WITNESS + 64 or 0 <= self.oob_first_offset < buf_size:
                raise ValueError("inconsistent violation count/offset")
        elif self.oob_count != 0 or self.oob_first_offset != -(2**31):
            raise ValueError("inconsistent clean count/offset")

    def to_dict(self) -> dict:
        return {"version": VERSION, "target_id": self.target_id, "gadget_id": self.gadget_id,
                "flags": self.flags, "oob_count": self.oob_count,
                "oob_first_offset": self.oob_first_offset,
                "witness_commitment": "sha256:" + self.witness_commitment.hex(),
                "target_source_hash": "sha256:" + self.target_source_hash.hex()}

    @classmethod
    def from_dict(cls, record: dict) -> "Statement":
        expected = {"version", "target_id", "gadget_id", "flags", "oob_count", "oob_first_offset", "witness_commitment", "target_source_hash"}
        if type(record) is not dict or set(record) != expected or type(record["version"]) is not int or record["version"] != VERSION:
            raise ValueError("unsupported statement shape/version")
        def digest(key: str) -> bytes:
            text = record[key]
            if type(text) is not str or len(text) != 71 or not text.startswith("sha256:") or text[7:] != text[7:].lower():
                raise ValueError("invalid statement digest")
            return bytes.fromhex(text[7:])
        result = cls(*(record[k] for k in ("target_id", "gadget_id", "flags", "oob_count", "oob_first_offset")), digest("witness_commitment"), digest("target_source_hash"))
        result.encode()
        return result
