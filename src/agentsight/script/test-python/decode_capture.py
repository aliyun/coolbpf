#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 eunomia-bpf org.

"""
Decode captured SSL traffic from AgentSight JSON output.
Identifies and decodes binary data (gzip, etc.) from captured events.
"""
import json
import gzip
import sys
from pathlib import Path


def is_http_request(data):
    """Check if data looks like an HTTP request."""
    return data.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH '))


def is_http_response(data):
    """Check if data looks like an HTTP response."""
    return data.startswith('HTTP/')


def is_gzip_data(data_bytes):
    """Check if data starts with gzip magic bytes."""
    return len(data_bytes) >= 2 and data_bytes[0] == 0x1f and data_bytes[1] == 0x8b


def decode_json_escaped_string(s):
    """
    Decode a JSON-escaped string to raw bytes.

    The sslsniff eBPF code outputs binary data as:
    - Invalid UTF-8 bytes: \\uXXXX escapes (json.loads converts to char with that codepoint)
    - Valid UTF-8 sequences: Raw UTF-8 bytes (json.loads decodes to Unicode chars)

    To recover original bytes:
    - Chars with codepoint < 256: use as byte value
    - Chars with codepoint >= 256: re-encode to UTF-8
    """
    result = bytearray()
    for c in s:
        cp = ord(c)
        if cp < 256:
            result.append(cp)
        else:
            # This came from valid UTF-8 in binary data
            result.extend(c.encode('utf-8'))
    return bytes(result)


def try_decompress_gzip(data_bytes):
    """Try to decompress gzip data."""
    try:
        decompressed = gzip.decompress(data_bytes)
        return decompressed.decode('utf-8', errors='replace')
    except Exception as e:
        return None


def analyze_event(event, event_num):
    """Analyze a single SSL event."""
    function = event.get('function', 'UNKNOWN')
    pid = event.get('pid', 0)
    length = event.get('len', 0)
    data = event.get('data', '')

    print(f"\n{'='*80}")
    print(f"Event #{event_num}: {function}")
    print(f"{'='*80}")
    print(f"PID: {pid}, Length: {length} bytes")

    # Determine data type
    if is_http_request(data):
        print(f"Type: HTTP Request")
        # Extract method and path
        first_line = data.split('\r\n')[0]
        print(f"Request Line: {first_line}")

        # Check for Authorization header
        if 'Authorization:' in data:
            print("⚠️  Contains Authorization header (API key)")
            lines = data.split('\r\n')
            for line in lines:
                if line.startswith('Authorization:'):
                    # Redact the actual token
                    print(f"   {line[:30]}... [REDACTED]")

        # Extract request body if present
        if '\r\n\r\n' in data:
            body = data.split('\r\n\r\n', 1)[1]
            if body:
                print(f"\nRequest Body:")
                try:
                    body_json = json.loads(body)
                    print(json.dumps(body_json, indent=2))
                except:
                    print(body)

    elif is_http_response(data):
        print(f"Type: HTTP Response")
        # Extract status line
        first_line = data.split('\r\n')[0]
        print(f"Status Line: {first_line}")

        # Check for interesting headers
        lines = data.split('\r\n')
        interesting_headers = [
            'Content-Type:', 'Content-Encoding:', 'Transfer-Encoding:',
            'openai-', 'x-ratelimit-', 'x-request-id:'
        ]

        print("\nKey Headers:")
        for line in lines:
            for header in interesting_headers:
                if line.lower().startswith(header.lower()):
                    print(f"   {line}")

        # Try to extract and decode body
        if '\r\n\r\n' in data:
            body = data.split('\r\n\r\n', 1)[1]
            if body and len(body) > 10:
                print(f"\nResponse Body: {len(body)} bytes (may be chunked/compressed)")
                # Try to decode as bytes for gzip check
                try:
                    body_bytes = decode_json_escaped_string(body)

                    # Check if it starts with chunk size (hex) followed by gzip data
                    if '\r\n' in body and len(body_bytes) > 10:
                        # Skip chunk size line
                        parts = body.split('\r\n', 1)
                        if len(parts) > 1:
                            chunk_size_line = parts[0]
                            chunk_data = parts[1]
                            chunk_data_bytes = decode_json_escaped_string(chunk_data)

                            if is_gzip_data(chunk_data_bytes):
                                print(f"   Detected: Chunked gzip data (chunk size: {chunk_size_line})")
                                # Try to decompress
                                decompressed = try_decompress_gzip(chunk_data_bytes)
                                if decompressed:
                                    print(f"   Decompressed Size: {len(decompressed)} bytes")
                                    print(f"\n{'─'*80}")
                                    print("DECOMPRESSED RESPONSE:")
                                    print(f"{'─'*80}")

                                    # Try to parse as JSON
                                    try:
                                        json_data = json.loads(decompressed)
                                        print(json.dumps(json_data, indent=2))

                                        # If it's an OpenAI response, highlight the message
                                        if 'choices' in json_data and len(json_data['choices']) > 0:
                                            print(f"\n{'─'*80}")
                                            print("🤖 AI ASSISTANT RESPONSE:")
                                            print(f"{'─'*80}")
                                            message = json_data['choices'][0].get('message', {})
                                            content = message.get('content', '')
                                            print(content)
                                    except json.JSONDecodeError:
                                        print(decompressed)

                    elif is_gzip_data(body_bytes):
                        print("   Detected: Gzip-compressed data")
                except Exception as e:
                    pass

    else:
        # Check if this is binary/compressed data
        try:
            data_bytes = decode_json_escaped_string(data)

            if is_gzip_data(data_bytes):
                print(f"Type: Gzip Compressed Data")
                print(f"Compressed Size: {len(data_bytes)} bytes")

                # Try to decompress
                decompressed = try_decompress_gzip(data_bytes)
                if decompressed:
                    print(f"Decompressed Size: {len(decompressed)} bytes")
                    print(f"\n{'─'*80}")
                    print("DECOMPRESSED CONTENT:")
                    print(f"{'─'*80}")

                    # Try to parse as JSON
                    try:
                        json_data = json.loads(decompressed)
                        print(json.dumps(json_data, indent=2))

                        # If it's an OpenAI response, highlight the message
                        if 'choices' in json_data and len(json_data['choices']) > 0:
                            print(f"\n{'─'*80}")
                            print("🤖 AI ASSISTANT RESPONSE:")
                            print(f"{'─'*80}")
                            message = json_data['choices'][0].get('message', {})
                            content = message.get('content', '')
                            print(content)
                    except json.JSONDecodeError:
                        # Not JSON, just print as text
                        print(decompressed)
                else:
                    print("⚠️  Failed to decompress gzip data")

            elif data.startswith('0\r\n\r\n'):
                print(f"Type: Chunked Transfer End Marker")

            elif len(data) < 50 and '\r\n' in data:
                print(f"Type: Chunked Transfer Metadata")
                print(f"Data: {repr(data)}")

            else:
                print(f"Type: Unknown/Binary Data")
                print(f"First 100 chars: {data[:100]}")
                if len(data) > 100:
                    print("   ...")

        except Exception as e:
            print(f"Type: Unknown (decode error: {e})")
            print(f"Raw data (first 200 chars): {data[:200]}")


def main():
    if len(sys.argv) != 2:
        print("Usage: decode_capture.py <json_capture_file>")
        sys.exit(1)

    capture_file = Path(sys.argv[1])
    if not capture_file.exists():
        print(f"Error: File not found: {capture_file}")
        sys.exit(1)

    print(f"Analyzing capture file: {capture_file}")
    print(f"File size: {capture_file.stat().st_size} bytes")

    # Read and parse JSON events
    events = []
    with open(capture_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                events.append(event)
            except json.JSONDecodeError as e:
                print(f"Warning: Failed to parse line {line_num}: {e}")

    print(f"Parsed {len(events)} events")

    # Analyze each event
    for i, event in enumerate(events, 1):
        analyze_event(event, i)

    print(f"\n{'='*80}")
    print("Analysis Complete")
    print(f"{'='*80}")
    print(f"Total events: {len(events)}")

    # Count event types
    read_count = sum(1 for e in events if e.get('function') == 'READ/RECV')
    write_count = sum(1 for e in events if e.get('function') == 'WRITE/SEND')
    print(f"READ/RECV events: {read_count}")
    print(f"WRITE/SEND events: {write_count}")


if __name__ == '__main__':
    main()
