import numpy as np
from rdhei_pec_auth import embed, recover_and_extract
from rdhei_pec_auth.pipeline import _labels


def _smooth(sz=96):
    yy, xx = np.mgrid[0:sz, 0:sz]
    return ((yy * 0.7 + xx * 0.6 + 30 * np.sin(xx / 9.0)) % 256).astype(np.uint8)


def test_reversible_extract_and_auth():
    img = _smooth(); key, auth = 2025, b"auth-key"
    cap = int(_labels(img).sum()) - 128
    payload = ''.join(np.random.default_rng(1).choice(list('01'), size=cap))
    stego, labels, used = embed(img, key, payload, auth)
    rec, ext, ok = recover_and_extract(stego, key, labels, auth)
    assert np.array_equal(rec, img)
    assert ext[:used] == payload[:used]
    assert ok is True


def test_tamper_detected():
    # Tamper a reference-row pixel (row 0 passes through to the recovered image),
    # so the change reaches the recovered content and the auth tag must flag it.
    img = _smooth(); key, auth = 11, b"k"
    stego, labels, _ = embed(img, key, '10' * 3000, auth)
    stego[0, 40] ^= 0xFF
    rec, _, ok = recover_and_extract(stego, key, labels, auth)
    assert ok is False


def test_wrong_auth_key_fails():
    img = _smooth();
    stego, labels, _ = embed(img, 5, '1' * 2000, b"right")
    _, _, ok = recover_and_extract(stego, 5, labels, b"wrong")
    assert ok is False
