# rdhei-pec-auth

**Reversible Data Hiding + authentication in encrypted images via multi-MSB prediction and prediction-error room reservation.**

MATLAB implementation with a verified NumPy reference, reproducing:

> F. Ren, Z. Zhang, K. Jiang, P. Zhang, T. Yang, *"Reversible data hiding and authentication scheme for encrypted image based on prediction error compression,"* Scientific Reports, 2025.

## Idea

Reserve-room-before-encryption. For each pixel the median-edge-detector (MED) predictor is evaluated from its causal neighbours; the number `t` of leading (most-significant) bits that agree with the prediction is recorded in a label map (which the paper compresses with adaptive coding). Those `t` MSBs are reusable — the decoder regenerates them from the prediction — so they carry the payload together with a **keyed authentication tag**.

The receiver re-predicts pixel-by-pixel in raster order, restores every reserved MSB, verifies the tag (detecting tampering), and recovers the original image exactly.

## Layout

```
src/pec_auth.m          MATLAB implementation (MED predictor / labels / embed / recover)
python/rdhei_pec_auth/  verified NumPy reference (keyed BLAKE2 authentication tag)
tests/                  pytest: reversibility, exact extraction, tamper detection
```

## Quick start

```bash
pip install -e python
pytest tests/
```

```matlab
cd src; tests_pec_auth
```

## Measured properties

- Bit-exact reversibility and exact payload extraction; ~4.6-5.4 bpp on standard images.
- **Authentication**: the tag verifies on untouched images; any change that reaches the recovered content makes the tag fail (tamper detected). A wrong authentication key also fails.

## License
MIT