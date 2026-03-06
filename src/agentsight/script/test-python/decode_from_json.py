#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 eunomia-bpf org.

"""Decode gzipped response from sslsniff JSON output."""
import gzip
import json
import sys

# The gzipped data chunk from event 4 in your output
# After "194\r\n" (chunk size in hex = 404 bytes)
json_str = r'"\u001f\u008b\b\u0000\u0000\u0000\u0000\u0000\u0000\u0003tR\u00cbN\u00c30\u0010\u00bc\u00ef\u00afx\u00f29\u008b6!\t\u0090KU\u00d1J=Tm\u0085\u0010\u0017\u0084V\u00c6~\u009b5x\u00fd,\u00fbmʇ\u00f2ߑ\u009d\u0090\u00dd\b\u00b8\u00f8\u00e0y3\u009e\u0019\u00bf\u00d7\u0002@\u0018-V T+Yuޖ\u009777\u00ff|C\u00b3G\u00bf\u00f9\u00fb'n.\u00ae\u007f*\u00f3\u00fb\u00fe\u00ca-\u00be\u00ffx\u00b9\u0012\u0093Ġ\u00fb\u0007T\u00fc\u00ce:Q\u00d4y\u008bl\u00c8\u00ed`\u0015P2&\u00d5\u00e9\u00d9r\u00ba\u009c\u00cd/\u0096\u008b\ft\u00a4\u00d1&\u00da\u00das\u00b9(\u009dtTΪ٢\u00ac\u00ce\u00cb\u00ealOn\u00c9(\u008cb\u0005\u00b7\u0005\u0000\u00c0k>\u0093M\u00a7\u00f1I\u00ac\u00a0\u009a\u00bc\u00dft\u0018\u00a3\\\u00a3X\u001d\u0086\u0000D \u009bn\u0084\u008c\u00d1D\u0096\u008e\u00c5d\u0000\u00159F\u0097\u009d\u00ffBk\t\u00b8ŀ\u0013h\u00e9?Ȁ\u00f0L\u00fd\u00b7\u00f1|\u00c0\u00a6\u008f2Yv\u00bd\u00b5#@:G,S\u00e4\u00ec\u00f4n\u008fl\u000f\u00de\u001a\u00e3Ll\u00eb\u00802\u0092K\u00efE&/2\u00ba-\u0000\u00eer\u00d6\u00feȾ\u00f0\u0081:\u00cf5\u00d3#f\u00d9\u00e9\u00e9NN\f\u0005\u000f\u00e0\u00bc\u00da\u0017!\u0098X\u00da\u0011p\u00a0\u001d\u00e9\u00d5\u001aY\u001a\u001bGm\t%U\u008bz\u00a0\u000e\u00d5\u00ca^\u001b\u001a\u0001\u00c5(\u00ddG;\u009fi\u00ef\u0092\u001b\u00b7\u001eTN\u00cf\u00e7_>0\u0000J\u00a1gԵ\u000f\u00a8\u008d:\u000e=\u008c\u0005L+\u00f8\u00d5ء\u00e7lYD\f\u001b\u00a3\u00b0f\u0083!\u00fd\u0085\u00c6F\u00f6v\u00b7\u0019\">GƮn\u008c[c\u00f0\u00c1\u00e4\u00f5H\u00df]l\u008b7\u0000\u0000\u0000\u00ff\u00ff"'

# Decode the JSON-escaped string to get raw bytes
decoded_str = json_str.encode('utf-8').decode('unicode_escape')
data_bytes = decoded_str.encode('latin1')  # Convert to raw bytes

print(f"Compressed size: {len(data_bytes)} bytes")

# Decompress
try:
    decompressed = gzip.decompress(data_bytes)
    print(f"Decompressed size: {len(decompressed)} bytes\n")
    print("Decompressed response:")
    print(decompressed.decode('utf-8'))

    # Try to parse as JSON
    try:
        response_json = json.loads(decompressed.decode('utf-8'))
        print("\nParsed JSON (formatted):")
        print(json.dumps(response_json, indent=2))

        if 'choices' in response_json:
            print("\n=== ASSISTANT RESPONSE ===")
            print(response_json['choices'][0]['message']['content'])
    except json.JSONDecodeError as e:
        print(f"\nCouldn't parse as JSON: {e}")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
