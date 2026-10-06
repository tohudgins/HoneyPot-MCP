"""An 8x16 bitmap font for the RDP honeypot's on-screen terminal.

Spleen 2.2.0 (8x16), https://github.com/fcambus/spleen, converted from its BDF file: the printable
ASCII range plus a few box-drawing and shade glyphs. Each glyph is 16 row bytes, most significant
bit leftmost. Spleen is distributed under the BSD 2-Clause licence; its notice is kept here as the
licence requires:

    Copyright (c) 2018-2026, Frederic Cambus
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

      * Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.

      * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
    BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
"""

from __future__ import annotations

GLYPH_WIDTH = 8
GLYPH_HEIGHT = 16

# code point -> 16 bytes (top row first)
GLYPHS: dict[int, bytes] = {
    32: bytes.fromhex("00000000000000000000000000000000"),
    33: bytes.fromhex("00001818181818181800181800000000"),
    34: bytes.fromhex("00666666660000000000000000000000"),
    35: bytes.fromhex("00006c6cfe6c6c6c6cfe6c6c00000000"),
    36: bytes.fromhex("00107ed0d0d07c16161616fc10000000"),
    37: bytes.fromhex("000006666c0c18183036666000000000"),
    38: bytes.fromhex("0000386c6c6c3870dacccc7a00000000"),
    39: bytes.fromhex("00181818180000000000000000000000"),
    40: bytes.fromhex("000e183030606060603030180e000000"),
    41: bytes.fromhex("0070180c0c060606060c0c1870000000"),
    42: bytes.fromhex("00000000663c18ff183c660000000000"),
    43: bytes.fromhex("000000000018187e1818000000000000"),
    44: bytes.fromhex("00000000000000000000181830000000"),
    45: bytes.fromhex("000000000000007e0000000000000000"),
    46: bytes.fromhex("00000000000000000000181800000000"),
    47: bytes.fromhex("0006060c0c181830306060c0c0000000"),
    48: bytes.fromhex("00007cc6c6cedef6e6c6c67c00000000"),
    49: bytes.fromhex("00001838785818181818187e00000000"),
    50: bytes.fromhex("00007cc606060c183060c6fe00000000"),
    51: bytes.fromhex("00007cc606063c060606c67c00000000"),
    52: bytes.fromhex("0000c0c0ccccccccfe0c0c0c00000000"),
    53: bytes.fromhex("0000fec6c0c0fc060606c67c00000000"),
    54: bytes.fromhex("00007cc6c0c0fcc6c6c6c67c00000000"),
    55: bytes.fromhex("0000fec606060c183030303000000000"),
    56: bytes.fromhex("00007cc6c6c67cc6c6c6c67c00000000"),
    57: bytes.fromhex("00007cc6c6c6c67e0606c67c00000000"),
    58: bytes.fromhex("00000000001818000000181800000000"),
    59: bytes.fromhex("00000000001818000000181830000000"),
    60: bytes.fromhex("0000060c1830606030180c0600000000"),
    61: bytes.fromhex("00000000007e00007e00000000000000"),
    62: bytes.fromhex("00006030180c06060c18306000000000"),
    63: bytes.fromhex("00007cc6060c18303000303000000000"),
    64: bytes.fromhex("0000007cc2dadadadadec07c00000000"),
    65: bytes.fromhex("00007cc6c6c6fec6c6c6c6c600000000"),
    66: bytes.fromhex("0000fcc6c6c6fcc6c6c6c6fc00000000"),
    67: bytes.fromhex("00007ec0c0c0c0c0c0c0c07e00000000"),
    68: bytes.fromhex("0000fcc6c6c6c6c6c6c6c6fc00000000"),
    69: bytes.fromhex("00007ec0c0c0f8c0c0c0c07e00000000"),
    70: bytes.fromhex("00007ec0c0c0f8c0c0c0c0c000000000"),
    71: bytes.fromhex("00007ec0c0c0dec6c6c6c67e00000000"),
    72: bytes.fromhex("0000c6c6c6c6fec6c6c6c6c600000000"),
    73: bytes.fromhex("00007e18181818181818187e00000000"),
    74: bytes.fromhex("00007e1818181818181818f000000000"),
    75: bytes.fromhex("0000c6c6c6ccf8ccc6c6c6c600000000"),
    76: bytes.fromhex("0000c0c0c0c0c0c0c0c0c07e00000000"),
    77: bytes.fromhex("0000c6eefed6c6c6c6c6c6c600000000"),
    78: bytes.fromhex("0000c6c6e6e6d6d6cecec6c600000000"),
    79: bytes.fromhex("00007cc6c6c6c6c6c6c6c67c00000000"),
    80: bytes.fromhex("0000fcc6c6c6fcc0c0c0c0c000000000"),
    81: bytes.fromhex("00007cc6c6c6c6c6c6d6d67c180c0000"),
    82: bytes.fromhex("0000fcc6c6c6fcc6c6c6c6c600000000"),
    83: bytes.fromhex("00007ec0c0c07c06060606fc00000000"),
    84: bytes.fromhex("0000ff18181818181818181800000000"),
    85: bytes.fromhex("0000c6c6c6c6c6c6c6c6c67e00000000"),
    86: bytes.fromhex("0000c6c6c6c6c6c6c66c381000000000"),
    87: bytes.fromhex("0000c6c6c6c6c6c6d6feeec600000000"),
    88: bytes.fromhex("0000c6c6c66c386cc6c6c6c600000000"),
    89: bytes.fromhex("0000c6c6c6c67e06060606fc00000000"),
    90: bytes.fromhex("0000fe06060c183060c0c0fe00000000"),
    91: bytes.fromhex("003e303030303030303030303e000000"),
    92: bytes.fromhex("00c0c06060303018180c0c0606000000"),
    93: bytes.fromhex("007c0c0c0c0c0c0c0c0c0c0c7c000000"),
    94: bytes.fromhex("0010386cc60000000000000000000000"),
    95: bytes.fromhex("0000000000000000000000000000fe00"),
    96: bytes.fromhex("0030180c000000000000000000000000"),
    97: bytes.fromhex("00000000007c067ec6c6c67e00000000"),
    98: bytes.fromhex("0000c0c0c0fcc6c6c6c6c6fc00000000"),
    99: bytes.fromhex("00000000007ec0c0c0c0c07e00000000"),
    100: bytes.fromhex("00000606067ec6c6c6c6c67e00000000"),
    101: bytes.fromhex("00000000007ec6c6fec0c07e00000000"),
    102: bytes.fromhex("00001e3030307c303030303000000000"),
    103: bytes.fromhex("00000000007ec6c6c6c6c67c0606fc00"),
    104: bytes.fromhex("0000c0c0c0fcc6c6c6c6c6c600000000"),
    105: bytes.fromhex("00001818003818181818181c00000000"),
    106: bytes.fromhex("00001818001818181818181818187000"),
    107: bytes.fromhex("0000c0c0c0ccd8f0f0d8ccc600000000"),
    108: bytes.fromhex("00003030303030303030301c00000000"),
    109: bytes.fromhex("0000000000ecd6d6d6d6c6c600000000"),
    110: bytes.fromhex("0000000000fcc6c6c6c6c6c600000000"),
    111: bytes.fromhex("00000000007cc6c6c6c6c67c00000000"),
    112: bytes.fromhex("0000000000fcc6c6c6c6c6fcc0c0c000"),
    113: bytes.fromhex("00000000007ec6c6c6c6c67e06060600"),
    114: bytes.fromhex("00000000007ec6c0c0c0c0c000000000"),
    115: bytes.fromhex("00000000007ec0c07c0606fc00000000"),
    116: bytes.fromhex("00003030307c30303030301e00000000"),
    117: bytes.fromhex("0000000000c6c6c6c6c6c67e00000000"),
    118: bytes.fromhex("0000000000c6c6c6c66c381000000000"),
    119: bytes.fromhex("0000000000c6c6d6d6d6d66e00000000"),
    120: bytes.fromhex("0000000000c66c38386cc6c600000000"),
    121: bytes.fromhex("0000000000c6c6c6c6c6c67e0606fc00"),
    122: bytes.fromhex("0000000000fe060c183060fe00000000"),
    123: bytes.fromhex("000e181818187070181818180e000000"),
    124: bytes.fromhex("00181818181818181818181818000000"),
    125: bytes.fromhex("0070181818180e0e1818181870000000"),
    126: bytes.fromhex("000000000000327e4c00000000000000"),
    183: bytes.fromhex("00000000000000181800000000000000"),
    9472: bytes.fromhex("00000000000000ff0000000000000000"),
    9474: bytes.fromhex("18181818181818181818181818181818"),
    9484: bytes.fromhex("000000000000001f1818181818181818"),
    9488: bytes.fromhex("00000000000000f81818181818181818"),
    9492: bytes.fromhex("181818181818181f0000000000000000"),
    9496: bytes.fromhex("18181818181818f80000000000000000"),
    9608: bytes.fromhex("ffffffffffffffffffffffffffffffff"),
    9617: bytes.fromhex("11441144114411441144114411441144"),
    9618: bytes.fromhex("55aa55aa55aa55aa55aa55aa55aa55aa"),
    9619: bytes.fromhex("dd77dd77dd77dd77dd77dd77dd77dd77"),
}


def glyph(char: str) -> bytes:
    """The 16 row bytes for `char`; anything the font lacks draws as a shaded block."""
    return GLYPHS.get(ord(char), GLYPHS[0x2591] if 0x2591 in GLYPHS else GLYPHS[63])
