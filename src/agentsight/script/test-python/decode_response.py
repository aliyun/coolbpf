#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 eunomia-bpf org.

"""Decode gzipped response from sslsniff output."""
import gzip
import json

# The gzipped chunk from the SSL capture (after the HTTP headers and "185\r\n")
# This is the third event in your output
hex_data = "1f8b080000000000000003745200cb4ee383301004bce72bac3d372849011fa01ea1a25710a80821141479b91811c3bd89b3b0242fd7764f791540c41859d9dd1ccacbf13c64049983310532752d1b43abdad5a952ad68d1f1feedb864f7fee917009bf77b75619637971fd7c5052d0cc0fcf3ebeca82a80ceb0b4cda6ad4859482dca291dc20209a9fcff2599312f2492004172b51075ad5523a4d0d376b2d00b29a6617696e791bed7560907f4309c674f0f098c7dc77fd83468343f61cebed161d2a0f708fbc42981f97981803676790e15875799ee286601ad4831ce0c13009d0f09c71d0e00d7dde7c19999e9bab1e0000dc184b3c248b90009ef700c8f66861ad008cf275e9905b6b82009acdb46539504130ddf261b3dc750dd893f4f6f6897685d6d5a2ac9be611400ce071c3bb4141e89bece1e93e300825ae19bfbb9ec403a512b254157da0f4a011c45008db267f60df20e2a3b00009241badf0066fed20fede2557a69ffa6df9d8f0ffd1e10025b4259b60e00a51200a789fb3587e1a3fdb7762c393a060f6ea38400049690b81453480f5c73f4e0efe0ffefecb1336e55a990a5deb54fc04e1dac936f9010000ffff030058519f690603000000"

# Convert hex string to bytes
data_bytes = bytes.fromhex(hex_data.replace("\\u00", ""))

# Decompress
try:
    decompressed = gzip.decompress(data_bytes)
    print("Decompressed response:")
    print(decompressed.decode('utf-8'))

    # Try to parse as JSON
    try:
        response_json = json.loads(decompressed.decode('utf-8'))
        print("\nParsed JSON:")
        print(json.dumps(response_json, indent=2))
    except json.JSONDecodeError as e:
        print(f"\nCouldn't parse as JSON: {e}")
except Exception as e:
    print(f"Error decompressing: {e}")
