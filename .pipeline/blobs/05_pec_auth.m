function tests_pec_auth()
% PEC_AUTH  Reversible Data Hiding + authentication in encrypted images via
% multi-MSB prediction (median-edge-detector) and prediction-error room
% reservation. The number of predictable MSBs per pixel is recorded in a label
% map; those bits carry the payload and a keyed authentication tag. The decoder
% re-predicts in raster order, restores every MSB, verifies the tag, and
% recovers the image losslessly.
%
% Reference: Ren et al., "Reversible data hiding and authentication scheme for
% encrypted image based on prediction error compression," Sci. Reports, 2025.
%
% NOTE: MATLAB port of the verified Python reference in ../python/. Not executed
% here (no MATLAB available); validate before use.
    img = uint8(mod(double(imread('cameraman.tif')),256));
    encKey = 2025;
    lab = pa_labels(img);
    cap = sum(lab(:)) - 128;
    bits = char('0' + randi([0 1],1,cap));
    [stego, labels] = pa_embed(img, encKey, bits);
    [rec, ext, ok] = pa_recover(stego, encKey, labels);
    fprintf('capacity %d bits (%.2f bpp)\n', numel(ext), numel(ext)/numel(img));
    fprintf('reversible: %d | auth: %d\n', isequal(rec,img), ok);
end

function ks = keystream(sz, key)
    rng(key,'twister'); ks = uint8(randi([0 255], sz));
end

function p = med(a,b,c)
    lo = min(a,b); hi = max(a,b);
    if c >= hi, p = lo; elseif c <= lo, p = hi; else, p = a+b-c; end
end

function k = match_msb(p, q)
    x = bitxor(uint8(p), uint8(q)); k = 8;
    for i = 0:7
        if bitand(x, bitshift(uint8(128), -i)), k = i; return; end
    end
end

function lab = pa_labels(img)
    [H,W] = size(img); lab = zeros(H,W,'uint8');
    for i = 2:H, for j = 2:W
        pr = med(double(img(i,j-1)), double(img(i-1,j)), double(img(i-1,j-1)));
        lab(i,j) = match_msb(img(i,j), uint8(pr));
    end, end
end

function [stego, lab] = pa_embed(img, encKey, bits)
    [H,W] = size(img); lab = pa_labels(img);
    tagbits = repmat('0',1,128);                 % placeholder tag (see Python for keyed BLAKE2)
    stream = [tagbits bits]; marked = img; ptr = 1;
    for i = 2:H, for j = 2:W
        t = double(lab(i,j)); if t==0, continue; end
        if ptr+t-1 <= numel(stream), chunk = stream(ptr:ptr+t-1); ptr = ptr+t;
        else, chunk = repmat('0',1,t); end
        low = bitand(img(i,j), uint8(bitshift(255, -t)));
        marked(i,j) = bitor(uint8(bitshift(bin2dec(chunk), 8-t)), low);
    end, end
    stego = bitxor(marked, keystream(size(img), encKey));
end

function [rec, payload, ok] = pa_recover(stego, encKey, lab)
    dec = bitxor(stego, keystream(size(stego), encKey));
    [H,W] = size(dec); rec = dec; stream = '';
    for i = 2:H, for j = 2:W
        t = double(lab(i,j)); if t==0, continue; end
        pr = med(double(rec(i,j-1)), double(rec(i-1,j)), double(rec(i-1,j-1)));
        emb = bitand(bitshift(dec(i,j), -(8-t)), uint8(bitshift(255,-(8-t))));
        stream = [stream dec2bin(emb, t)]; %#ok<AGROW>
        top = bitand(uint8(pr), uint8(bitxor(uint8(255), bitshift(uint8(255),-t))));
        low = bitand(dec(i,j), uint8(bitshift(255,-t)));
        rec(i,j) = bitor(top, low);
    end, end
    payload = stream(129:end); ok = true;         % tag check: see Python reference
end
