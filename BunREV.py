import struct
import os
import re
import sys
import binascii
from typing import List, Dict, Tuple, BinaryIO

class BunFile:
    def __init__(self, filepath: str):

        self.filepath = filepath
        self.header = {}
        self.entries = []
        self.data = b''
        self.game_name = ""
        self.base_name = os.path.splitext(os.path.basename(filepath))[0]
        
        match = re.search(r'SCENE_([A-Za-z0-9]+)_', self.base_name)
        if match:
            self.game_name = match.group(1)
            print(f"Detected game identifier: {self.game_name}")
        
    def read(self):
        """Read and parse the BUN file"""
        with open(self.filepath, 'rb') as f:
            
            self.data = f.read()
        
        self._parse_header()
        self._extract_entries()
    
    def _parse_header(self):
        """Parse the BUN file header"""
        
        self.header['raw_header'] = self.data[:32]
        print(f"Header (first 32 bytes): {binascii.hexlify(self.data[:32]).decode()}")
        
        try:    
            self.header['signature'] = self.data[:4]
            self.header['version'] = struct.unpack('<I', self.data[4:8])[0]
            self.header['file_count_or_offset'] = struct.unpack('<I', self.data[8:12])[0]
            
            print(f"Possible file signature: {binascii.hexlify(self.header['signature']).decode()}")
            print(f"Possible version or flags: {self.header['version']}")
            print(f"Possible file count or offset: {self.header['file_count_or_offset']}")

        except Exception as e:
            print(f"Error parsing header: {str(e)}")
    
    def _extract_entries(self):
        """Extract file entries using a smarter approach based on patterns"""
        
        if self.game_name:
            zpm_pattern = re.compile(bytes(f"{self.game_name}ZPM_[A-Za-z0-9_]+", 'ascii'))
            zpm_matches = list(zpm_pattern.finditer(self.data))
            
            if zpm_matches:
                print(f"Found {len(zpm_matches)} ZPM entries")
                for match in zpm_matches:
                    name = match.group(0).decode('ascii')
                    pos = match.start()
                    
                    self.entries.append({
                        'type': 'zpm',
                        'name': name,
                        'offset': pos,
                        'data_offset': pos + len(name),
                        'data_size': 2048  
                    })
        
        xml_pattern = re.compile(b'<[A-Za-z][A-Za-z0-9]*[^>]*>[^<]*</[A-Za-z][A-Za-z0-9]*>')
        xml_matches = list(xml_pattern.finditer(self.data))
        if xml_matches:
            print(f"Found {len(xml_matches)} XML-like structures")
            for match in xml_matches:
                xml_data = match.group(0)
                self.entries.append({
                    'type': 'xml',
                    'name': f"xml_content_{match.start()}",
                    'offset': match.start(),
                    'data_offset': match.start(),
                    'data_size': len(xml_data)
                })
        
        resource_pattern = re.compile(b'(TOOL|ENGINE|LIGHT|GLOBAL|DEFAULT|FCOP|PERP|SHADOW|CUFFS)[A-Za-z0-9_]*')
        resource_matches = list(resource_pattern.finditer(self.data))
        if resource_matches:
            print(f"Found {len(resource_matches)} resource identifiers")
            for match in resource_matches:
                name = match.group(0).decode('ascii')
                
                if not any(e['offset'] == match.start() for e in self.entries):
                    
                    self.entries.append({
                        'type': 'resource',
                        'name': name,
                        'offset': match.start(),
                        'data_offset': match.start() + len(name),
                        'data_size': 4096  
                    })
        
        self.entries.sort(key=lambda e: e['offset'])
        
        for i in range(len(self.entries) - 1):
            next_offset = self.entries[i+1]['offset']
            current_end = self.entries[i]['data_offset'] + self.entries[i]['data_size']
            
            if current_end > next_offset:
                
                self.entries[i]['data_size'] = next_offset - self.entries[i]['data_offset']
    
    def extract_all(self, output_dir: str):
        """Extract all files to the specified directory with better organization"""
        if not self.entries:
            print("No files identified for extraction")
            return
        
        for entry_type in set(e['type'] for e in self.entries):
            type_dir = os.path.join(output_dir, entry_type)
            os.makedirs(type_dir, exist_ok=True)

        print(f"Extracting {len(self.entries)} files...")
        for i, entry in enumerate(self.entries):
            
            filename = f"{i:03d}_{entry['name']}"
            
            type_dir = os.path.join(output_dir, entry['type'])
            output_path = os.path.join(type_dir, filename)
            
            start = entry['data_offset']
            end = start + entry['data_size']
            
            if start < len(self.data) and end <= len(self.data):
                with open(output_path, 'wb') as f:
                    f.write(self.data[start:end])
                print(f"Extracted: {filename} ({entry['data_size']} bytes) as {entry['type']}")
            else:
                print(f"Skipped {filename}: Invalid data range")
    
    def analyze_structure(self, output_dir: str):
        """Analyze the file structure and save a report"""
        os.makedirs(output_dir, exist_ok=True)
        report_path = os.path.join(output_dir, "structure_analysis.txt")
        
        with open(report_path, 'w') as f:
            f.write(f"BUN FILE STRUCTURE ANALYSIS\n")
            f.write(f"==========================\n")
            f.write(f"File: {self.filepath}\n")
            f.write(f"Size: {len(self.data):,} bytes\n\n")
            
            f.write("HEADER INFORMATION\n")
            f.write("-----------------\n")
            for key, value in self.header.items():
                if key == 'raw_header':
                    f.write(f"Raw header (hex): {binascii.hexlify(value).decode()}\n")
                else:
                    f.write(f"{key}: {value}\n")
            
            f.write("\nFILE ENTRIES\n")
            f.write("-----------\n")
            for i, entry in enumerate(self.entries):
                f.write(f"Entry 
                f.write(f"  Type: {entry['type']}\n")
                f.write(f"  Name: {entry['name']}\n")
                f.write(f"  Offset: {entry['offset']}\n")
                f.write(f"  Data Offset: {entry['data_offset']}\n")
                f.write(f"  Data Size: {entry['data_size']}\n")
                
                start = entry['data_offset']
                hex_data = binascii.hexlify(self.data[start:start+min(16, entry['data_size'])]).decode()
                f.write(f"  Data preview: {hex_data}...\n\n")
            
        print(f"Structure analysis written to {report_path}")
    
    def dump_hex_analysis(self, output_dir: str):
        """Create a comprehensive hex dump for analysis"""
        os.makedirs(output_dir, exist_ok=True)
        
        header_path = os.path.join(output_dir, "header_hex.txt")
        with open(header_path, 'w') as f:
            f.write("HEADER HEX DUMP\n")
            f.write("==============\n\n")
            
            self._write_hex_dump(f, self.data[:256], 0)

        print(f"Header hex dump written to {header_path}")

    def _write_hex_dump(self, file, data, start_offset=0):
        """Helper method to write formatted hex dumps"""
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            
            file.write(f"{start_offset+i:08x}: ")
            
            hex_values = ' '.join(f"{b:02x}" for b in chunk)
            file.write(f"{hex_values.ljust(48)} ")
            
            ascii_values = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            file.write(f"{ascii_values}\n")

def main():
    
    if len(sys.argv) < 2:
        print("Usage: python main.py <path_to_bun_file>")
        sys.exit(1)
    
    bun_file_path = sys.argv[1]
    
    output_base = os.path.join(".", "Output")
    output_dir = os.path.join(output_base, os.path.splitext(os.path.basename(bun_file_path))[0])
    
    print(f"Processing: {bun_file_path}")
    print(f"Output directory: {output_dir}")
    
    try:
        
        os.makedirs(output_dir, exist_ok=True)
        
        bun_file = BunFile(bun_file_path)
        bun_file.read()
        bun_file.analyze_structure(output_dir)
        bun_file.dump_hex_analysis(output_dir)
        bun_file.extract_all(output_dir)
        print(f"Parsing complete. Results saved to {output_dir}")
    except Exception as e:
        print(f"Error processing file: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
