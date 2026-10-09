import pytest

from bitchat_web.protocol import FrameDecoder, encode_frame


def test_decoder_handles_fragmented_and_multiple_frames():
    first = encode_frame({"id": "one"})
    second = encode_frame({"id": "two"})
    decoder = FrameDecoder()
    assert decoder.feed(first[:3]) == []
    assert decoder.feed(first[3:] + second) == [{"id": "one"}, {"id": "two"}]


def test_frame_size_is_limited():
    with pytest.raises(ValueError):
        encode_frame({"body": "x" * (64 * 1024)})
