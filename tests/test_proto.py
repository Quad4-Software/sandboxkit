# SPDX-License-Identifier: 0BSD
"""Unit tests for the child/parent wire protocol."""

import errno

from sandboxkit import _proto


def test_record_roundtrip() -> None:
    data = _proto.encode_record(_proto.REC_OSERROR, errno.EACCES, b"denied")
    record = _proto.decode_record(data)
    assert record is not None
    assert record.kind == _proto.REC_OSERROR
    assert record.errno == errno.EACCES
    assert record.message == "denied"


def test_record_empty_message() -> None:
    record = _proto.decode_record(_proto.encode_record(_proto.REC_OK, 0))
    assert record is not None
    assert record.kind == _proto.REC_OK
    assert record.message == ""


def test_record_message_truncated() -> None:
    data = _proto.encode_record(_proto.REC_EXCEPTION, 0, b"x" * (_proto.MSG_CAP * 2))
    record = _proto.decode_record(data)
    assert record is not None
    assert len(record.message) == _proto.MSG_CAP


def test_decode_incomplete() -> None:
    assert _proto.decode_record(b"") is None
    assert _proto.decode_record(b"\x00\x01") is None


def test_decode_extra_bytes_ignored() -> None:
    data = _proto.encode_record(_proto.REC_SETUP, errno.EIO, b"boom")
    record = _proto.decode_record(data + b"trailing")
    assert record is not None
    assert record.message == "boom"


def test_ctl_layout() -> None:
    assert _proto.CTL.size == 3
    code, err = _proto.CTL.unpack(_proto.CTL.pack(_proto.CTL_USERNS_ERR, errno.EPERM))
    assert code == _proto.CTL_USERNS_ERR
    assert err == errno.EPERM


def test_pidmsg_layout() -> None:
    assert _proto.PIDMSG.size == 4
    (pid,) = _proto.PIDMSG.unpack(_proto.PIDMSG.pack(4242))
    assert pid == 4242
