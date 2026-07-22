"""
rdhei-pec-auth : Reversible Data Hiding + authentication in encrypted images
via multi-MSB prediction and prediction-error room reservation.

Reference implementation of:
    F. Ren, Z. Zhang, K. Jiang, P. Zhang, T. Yang, "Reversible data hiding and
    authentication scheme for encrypted image based on prediction error
    compression," Scientific Reports, 2025.

Idea
----
Reserve-room-before-encryption.  For each pixel the median-edge-detector (MED)
predictor is evaluated from its causal neighbours; the number ``t`` of leading
(most-significant) bits that agree with the prediction is recorded in a label
map (which the paper compresses with adaptive coding).  Those ``t`` MSBs are
freely reusable because the decoder can regenerate them from the prediction, so
they carry the payload together with a keyed authentication tag.  The receiver
re-predicts pixel-by-pixel in raster order, restoring every reserved MSB and
verifying the tag to detect tampering, then recovers the original image exactly.

NumPy + hashlib; provably reversible.  Validator for the MATLAB port in ``src/``.
"""
from __future__ import annotations
import numpy as np, hashlib


def keystream(shape, key):
    return np.random.default_rng(key).integers(0, 256, size=shape, dtype=np.uint8)

def _med(a, b, c):   # left, up, up-left  -> MED prediction
    lo, hi = min(a, b), max(a, b)
    if c >= hi: return lo
    if c <= lo: return hi
    return a + b - c

def _match_msb(p, q):
    """number of leading bits shared by two bytes (0..8)."""
    x = p ^ q
    for k in range(8):
        if x & (0x80 >> k):
            return k
    return 8


def _labels(img):
    """Per-pixel count of predictable MSBs (0 for the reference row/column)."""
    H, W = img.shape
    lab = np.zeros((H, W), dtype=np.uint8)
    for i in range(1, H):
        for j in range(1, W):
            pred = _med(int(img[i, j-1]), int(img[i-1, j]), int(img[i-1, j-1]))
            lab[i, j] = _match_msb(int(img[i, j]), pred)
    return lab


def embed(img, enc_key, bits, auth_key=b"key"):
    """Reserve MSBs via prediction, embed payload + auth tag, encrypt.
    Returns (stego_encrypted, labels, used_bits)."""
    H, W = img.shape
    lab = _labels(img)
    tag = hashlib.blake2b(img.tobytes(), key=auth_key, digest_size=16).hexdigest()
    tag_bits = "".join(format(b, "08b") for b in bytes.fromhex(tag))
    stream = tag_bits + bits                     # authentication first, then payload
    marked = img.copy()
    ptr = 0
    for i in range(1, H):
        for j in range(1, W):
            t = int(lab[i, j])
            if t == 0:
                continue
            chunk = stream[ptr:ptr + t]
            if len(chunk) < t:
                chunk = chunk + "0" * (t - len(chunk))
            else:
                ptr += t
            low = int(img[i, j]) & (0xFF >> t)   # keep the 8-t low bits
            marked[i, j] = (int(chunk, 2) << (8 - t)) | low
    stego = np.bitwise_xor(marked, keystream(img.shape, enc_key))
    return stego, lab, min(ptr, len(stream)) - len(tag_bits)


def recover_and_extract(stego, enc_key, labels, auth_key=b"key"):
    """Decrypt, restore MSBs from prediction (raster order), extract payload,
    verify the authentication tag.  Returns (recovered, payload, auth_ok)."""
    dec = np.bitwise_xor(stego, keystream(stego.shape, enc_key))
    H, W = dec.shape
    rec = dec.copy()
    stream = []
    for i in range(1, H):
        for j in range(1, W):
            t = int(labels[i, j])
            if t == 0:
                continue
            pred = _med(int(rec[i, j-1]), int(rec[i-1, j]), int(rec[i-1, j-1]))
            embedded = (int(dec[i, j]) >> (8 - t)) & (0xFF >> (8 - t))
            stream.append(format(embedded, f"0{t}b"))
            top = pred & (0xFF ^ (0xFF >> t))    # true top t bits from prediction
            low = int(dec[i, j]) & (0xFF >> t)
            rec[i, j] = top | low
    allbits = "".join(stream)
    tag_bits, payload = allbits[:128], allbits[128:]
    tag = hashlib.blake2b(rec.tobytes(), key=auth_key, digest_size=16).hexdigest()
    exp = "".join(format(b, "08b") for b in bytes.fromhex(tag))
    return rec, payload, (tag_bits == exp)


def entropy(img):
    h = np.bincount(img.flatten(), minlength=256).astype(float)
    h = h[h > 0] / img.size
    return float(-(h * np.log2(h)).sum())
