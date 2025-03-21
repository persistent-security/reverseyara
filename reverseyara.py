# Copyright (c) Persistent Security Industries 2025
# https://www.persistent-security.net
# This program is licensed under the GNU General Public License (GPL).
# See the LICENSE file for more details.

import re
import sys
import random
import struct
import plyara
import os  # added import for os
from typing import List, Dict, Any
from rich.console import Console

console = Console()

# Add helper function to join elements with random binary padding
def join_with_random_padding(elements: list) -> bytes:
    result = b""
    for i, elem in enumerate(elements):
        result += elem
        if i != len(elements) - 1:
            pad = bytes(random.randint(0, 255) for _ in range(random.randint(1, 16)))
            result += pad
    return result

def create_minimal_pdf(content_set: set) -> bytes:
    """Create a minimal valid PDF containing the specified content from a set.
       The content is inserted as produced by the rule conditions with random binary padding.
    """
    content_bytes = join_with_random_padding(list(content_set))
    # Generate object IDs
    catalog_obj_id = 1
    pages_obj_id = 2
    page_obj_id = 3
    content_obj_id = 4

    # PDF Header
    pdf = b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n"

    # Catalog object
    pdf += f"{catalog_obj_id} 0 obj\n".encode()
    pdf += b"<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"

    # Pages object
    pdf += f"{pages_obj_id} 0 obj\n".encode()
    pdf += b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"

    # Page object
    pdf += f"{page_obj_id} 0 obj\n".encode()
    pdf += f"<< /Type /Page /Parent 2 0 R /Resources << >> /Contents {content_obj_id} 0 R /MediaBox [0 0 612 792] >>\nendobj\n".encode()

    # Content stream object
    content_obj_pos = len(pdf)
    pdf += f"{content_obj_id} 0 obj\n".encode()
    pdf += f"<< /Length {len(content_bytes)} >>\nstream\n".encode()
    pdf += content_bytes
    pdf += b"\nendstream\nendobj\n"

    # Cross-reference table
    xref_pos = len(pdf)
    pdf += b"xref\n"
    pdf += f"0 {content_obj_id + 1}\n".encode()
    pdf += b"0000000000 65535 f \n"  # Object 0 is always free
    offsets = [18, 38, 68, content_obj_pos]
    for offset in offsets:
        pdf += f"{offset:010d} 00000 n \n".encode()

    # Trailer
    pdf += b"trailer\n"
    pdf += f"<< /Size {content_obj_id + 1} /Root {catalog_obj_id} 0 R >>\n".encode()
    pdf += b"startxref\n"
    pdf += f"{xref_pos}\n".encode()
    pdf += b"%%EOF"

    return pdf

def create_minimal_pe(content_set: set) -> bytes:
    """Create a minimal valid Windows PE file containing the specified content from a set.
       The content is inserted as produced by the rule conditions with random binary padding.
    """
    content_bytes = join_with_random_padding(list(content_set))
    # DOS Header
    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)  # e_lfanew points to PE header

    # PE Header
    pe_header = b"PE\x00\x00"  # Signature
    pe_header += struct.pack("<H", 0x14C)  # Machine (Intel 386)
    pe_header += struct.pack("<H", 1)  # Number of sections
    pe_header += b"\x00" * 12  # Timestamp, Pointer to Symbol Table, Number of Symbols
    pe_header += struct.pack("<H", 0xE0)  # Size of Optional Header
    pe_header += struct.pack("<H", 0x103)  # Characteristics (Executable, 32-bit)

    # Optional Header
    optional_header = struct.pack("<H", 0x10B)  # Magic (PE32)
    valid_opcodes = [
        0x90,  # NOP
        0xCC,  # INT3
        0x40,  # INC EAX
        0x48,  # DEC EAX
        0x50,  # PUSH EAX
        0x58,  # POP EAX
        0x31,  # XOR
        0x89,  # MOV
        0xB8,  # MOV immediate to EAX
    ]
    optional_header += bytes(random.choice(valid_opcodes) for _ in range(94))  # Fill with random valid opcodes

    # Section Header
    section_header = b".text\x00\x00\x00"  # Section name
    section_header += struct.pack("<I", len(content_bytes))  # Virtual size
    section_header += struct.pack("<I", 0x1000)  # Virtual address
    section_header += struct.pack("<I", len(content_bytes))  # Size of raw data
    section_header += struct.pack("<I", 0x200)  # Pointer to raw data
    section_header += b"\x00" * 16  # Placeholder for the rest of the section header

    # Section Content
    padding_size = 512 - len(content_bytes)  # Align to 512 bytes
    high_entropy_padding = bytes(random.choice(valid_opcodes) for _ in range(padding_size))
    section_content = content_bytes + high_entropy_padding

    return dos_header + pe_header + optional_header + section_header + section_content

def create_minimal_html(content_set: set) -> bytes:
    """Create a minimal valid HTML file containing the specified content from a set.
       The content is inserted as produced by the rule conditions.
    """
    content_bytes = b'\n'.join(list(content_set))  # was: list(content_set) * 3
    # Convert bytes to string for HTML embedding (assuming utf-8 content)
    try:
        content = content_bytes.decode('utf-8', errors='replace')
    except Exception:
        content = "<pre>Could not decode content.</pre>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>YARA Rule Output</title>
    <style>
        body {{
            font-family: monospace;
            white-space: pre-wrap;
        }}
    </style>
</head>
<body>
{content}
</body>
</html>
"""
    return html.encode('utf-8')

def create_minimal_ps1(content_set: set) -> bytes:
    """Create a minimal valid PowerShell script containing the specified content from a set.
       The content is inserted as produced by the rule conditions.
    """
    content_bytes = b'\n'.join(list(content_set))  # was: list(content_set) * 3
    content = content_bytes.decode('utf-8', errors='replace')
    ps1 = "# Minimal PowerShell Script generated by reverseyara.py\n" + content
    return ps1.encode('utf-8')

def create_minimal_bat(content_set: set) -> bytes:
    """Create a minimal valid Batch script containing the specified content from a set.
       The content is inserted as produced by the rule conditions.
    """
    content_bytes = b'\n'.join(list(content_set))  # was: list(content_set) * 3
    content = content_bytes.decode('utf-8', errors='replace')
    bat = "@echo off\r\n:: Minimal Batch Script generated by reverseyara.py\r\n" + content
    return bat.encode('utf-8')

# Add new helper for raw output
def create_raw(content_set: set) -> bytes:
    """Create a raw output file containing only the extracted strings joined by newline."""
    return b'\n'.join(list(content_set))

def process_byte_string(value: str) -> bytes:
    """Process a YARA byte string into its binary representation."""
    clean_value = value.strip("{} \t\n")
    byte_values = []
    hex_pattern = re.findall(r'([0-9A-Fa-f]{2}|\?\?|\[[0-9]+\])', clean_value)

    for hex_byte in hex_pattern:
        if (hex_byte == '??'):  # Wildcard byte
            byte_values.append(0x90)  # NOP instruction as a placeholder
        elif hex_byte.startswith('['):  # Range like [2]
            count = int(re.search(r'\[([0-9]+)\]', hex_byte).group(1))
            byte_values.extend([0x90] * count)  # NOP instruction as placeholder
        else:
            byte_values.append(int(hex_byte, 16))

    return bytes(byte_values)

def process_regex_string(value: str) -> bytes:
    """Process a YARA regex string into its binary representation."""
    value = value.strip('/^$')
    value = bytes(value, 'utf-8').decode('unicode_escape')
    value = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), value)
    return bytes(value, 'utf-8')

def extract_strings_from_rules(parsed_rules: List[Dict[str, Any]]) -> List[bytes]:
    """Extract and convert all strings from parsed YARA rules."""
    all_strings = []

    for rule in parsed_rules:
        if 'strings' not in rule:
            continue

        for string in rule['strings']:
            if 'value' not in string or 'type' not in string:
                continue

            value = string['value']

            if string['type'] == 'byte':
                all_strings.append(process_byte_string(value))
            elif string['type'] == 'regex':
                all_strings.append(process_regex_string(value))
            else:  # Plain string
                all_strings.append(bytes(bytes(value, 'utf-8').decode('unicode_escape'), 'utf-8'))

    return all_strings

def process_rule_conditions(parsed_rules: List[Dict[str, Any]], content: set) -> set:
    """
    For each parsed rule that has a condition, evaluate the condition and update
    the set of strings to ensure it fulfills the condition.
    """
    for rule in parsed_rules:
        if 'condition' in rule:
            condition = rule['condition']
            try:
                if "any of them" in condition:
                    strings = [s['value'].encode('utf-8') for s in rule.get('strings', []) if 'value' in s]
                    if not any(s in content for s in strings):
                        content.add(strings[0])
                elif "all of them" in condition:
                    strings = [s['value'].encode('utf-8') for s in rule.get('strings', []) if 'value' in s]
                    for s in strings:
                        content.add(s)
                elif "1 of them" in condition:
                    strings = [s['value'].encode('utf-8') for s in rule.get('strings', []) if 'value' in s]
                    if sum(1 for s in strings if s in content) != 1:
                        content.add(strings[0])
                elif re.match(r"\d+ of \$[a-zA-Z]\*", condition):
                    match = re.match(r"(\d+) of (\$[a-zA-Z]\*)", condition)
                    if match:
                        min_count = int(match.group(1))
                        prefix = match.group(2)[1:]
                        strings = [s['value'].encode('utf-8') for s in rule.get('strings', [])
                                   if 'name' in s and s['name'].startswith(prefix)]
                        if sum(1 for s in strings if s in content) < min_count:
                            for s in strings[:min_count]:
                                content.add(s)
                else:
                    console.print(f"Warning: Unsupported condition - {condition}", style="bold yellow")
            except Exception as e:
                console.print(f"Error processing condition '{condition}': {e}", style="bold red")
    return content

def send_over_net(content_set: set, host: str, port: int) -> None:
    """Open a TCP connection to the host and port and send the signatures with random padding."""
    import socket
    data = join_with_random_padding(list(content_set))
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            sock.sendall(data)
            console.print(f"Successfully sent signatures to {host}:{port}", style="bold green")
    except Exception as e:
        console.print(f"Error sending data over TCP: {e}", style="bold red")
        sys.exit(1)

def parse_yara_and_generate_file(input_file: str, output_file: str, file_type: str) -> None:
    """Parse YARA rules and generate a file containing the extracted signatures and rule conditions."""
    try:
        with open(input_file, 'r') as yara_file:
            yara_rules = yara_file.read()
    except FileNotFoundError:
        console.print(f"Error: File not found - {input_file}", style="bold red")
        sys.exit(1)

    parser = plyara.Plyara()
    try:
        parsed_rules = parser.parse_string(yara_rules)
    except Exception as e:
        console.print(f"Error parsing YARA rules: {e}", style="bold red")
        sys.exit(1)

    all_strings = extract_strings_from_rules(parsed_rules)
    content_set = set(all_strings)
    content_set = process_rule_conditions(parsed_rules, content_set)

    file_creators = {
        "pdf": create_minimal_pdf,
        "exe": create_minimal_pe,
        "html": create_minimal_html,
        "ps1": create_minimal_ps1,
        "bat": create_minimal_bat,
    }

    creator = file_creators.get(file_type)
    if not creator:
        console.print(f"Error: Unsupported file type - {file_type}", style="bold red")
        sys.exit(1)
    file_data = creator(content_set)

    try:
        with open(output_file, 'wb') as output_file_obj:
            output_file_obj.write(file_data)
    except Exception as e:
        console.print(f"Error writing output file: {e}", style="bold red")
        sys.exit(1)

    console.print(f"Successfully created {file_type.upper()} file: {output_file}", style="bold green")
    if file_type in ("exe", "ps1", "bat"):
        console.print("Disclaimer: This is just a proof-of-concept. NEVER run any executables resulting from this, even if they should not work.",
                      style="bold yellow")

# Modified main function to derive type from output file extension.
def main():
    if len(sys.argv) < 2:
        console.print("Usage: python reverseyara.py <yara_file> [output_file/net] ...", style="bold blue")
        sys.exit(1)

    input_yara_file = sys.argv[1]
    output_spec = sys.argv[2] if len(sys.argv) > 2 else "output.raw"
    
    # Process YARA file and build the content set
    try:
        with open(input_yara_file, 'r') as yara_file:
            yara_rules = yara_file.read()
    except FileNotFoundError:
        console.print(f"Error: File not found - {input_yara_file}", style="bold red")
        sys.exit(1)
    parser = plyara.Plyara()
    try:
        parsed_rules = parser.parse_string(yara_rules)
    except Exception as e:
        console.print(f"Error parsing YARA rules: {e}", style="bold red")
        sys.exit(1)
    all_strings = extract_strings_from_rules(parsed_rules)
    content_set = set(all_strings)
    content_set = process_rule_conditions(parsed_rules, content_set)

    if output_spec.lower() == "net":
        # In net mode, expect: python reverseyara.py <yara_file> net <target_host> <target_port>
        if len(sys.argv) < 4:
            console.print("Usage for net: python reverseyara.py <yara_file> net <target_host> <target_port>", style="bold blue")
            sys.exit(1)
        target_host = sys.argv[3]
        try:
            target_port = int(sys.argv[4])
        except ValueError:
            console.print("Error: Port must be an integer.", style="bold red")
            sys.exit(1)
        send_over_net(content_set, target_host, target_port)
    else:
        ext = os.path.splitext(output_spec)[1].lower()
        # Map file extension to creator functions; default to raw if not found.
        creators = {
            ".pdf": create_minimal_pdf,
            ".exe": create_minimal_pe,
            ".html": create_minimal_html,
            ".ps1": create_minimal_ps1,
            ".bat": create_minimal_bat,
        }
        creator = creators.get(ext, create_raw)
        file_data = creator(content_set)
        try:
            with open(output_spec, 'wb') as fout:
                fout.write(file_data)
        except Exception as e:
            console.print(f"Error writing output file: {e}", style="bold red")
            sys.exit(1)
        console.print(f"Successfully created {output_spec}", style="bold green")
        if ext in (".exe", ".ps1", ".bat"):
            console.print("Disclaimer: This is just a proof-of-concept. NEVER run any executables resulting from this, even if they should not work.",
                          style="bold yellow")

if __name__ == "__main__":
    main()
