# SPDX-License-Identifier: 0BSD
"""Wire protocol between the sandboxed child and its parent.

All messages are fixed-size binary records so the parent can parse them
without trusting the child: a malformed child produces at most a failed
Result, never a confused parent.
"""

from __future__ import annotations

import struct
from typing import NamedTuple

__all__ = [
    "ACK",
    "CTL",
    "CTL_USERNS_ERR",
    "CTL_USERNS_NONE",
    "CTL_USERNS_OK",
    "MSG_CAP",
    "PIDMSG",
    "REC",
    "REC_EXCEPTION",
    "REC_EXEC",
    "REC_OK",
    "REC_OSERROR",
    "REC_SETUP",
    "Record",
    "decode_record",
    "encode_record",
]

# Child to parent, first message: how the CLONE_NEWUSER unshare went.
CTL_USERNS_NONE = 0
CTL_USERNS_OK = 1
CTL_USERNS_ERR = 2
CTL = struct.Struct("!BH")

# Parent to child: 0 on success, otherwise the errno of the failed write.
ACK = struct.Struct("!B")

# Child to parent: pid of the payload process in the parent pid namespace.
PIDMSG = struct.Struct("!i")

# Payload to parent: outcome record kind.
REC_OK = 0
REC_OSERROR = 1
REC_EXCEPTION = 2
REC_SETUP = 3
REC_EXEC = 4
REC = struct.Struct("!BiH")

MSG_CAP = 512


class Record(NamedTuple):
    """Decoded outcome record from the payload process."""

    kind: int
    errno: int
    message: str


def encode_record(kind: int, err: int, message: bytes = b"") -> bytes:
    """Encode one outcome record, truncating message to MSG_CAP."""
    return REC.pack(kind, err, min(len(message), MSG_CAP)) + message[:MSG_CAP]


def decode_record(data: bytes) -> Record | None:
    """Decode a complete outcome record, or None when data is missing."""
    if len(data) < REC.size:
        return None
    kind, err, msg_len = REC.unpack_from(data)
    message = data[REC.size : REC.size + msg_len].decode(errors="replace")
    return Record(kind, err, message)
