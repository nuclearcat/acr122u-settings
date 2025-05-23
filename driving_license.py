#!/usr/bin/env python3
"""
(AI written)
Java Card Driving License Reader
Specialized for reading driving license data from Java Cards
Supports multiple international standards and formats
"""

from smartcard.System import readers
from smartcard.util import toHexString, toBytes
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import CardRequestTimeoutException, NoCardException
import time
import struct

class DrivingLicenseReader:
    def __init__(self):
        self.connection = None
        self.reader = None
        self.cardservice = None
        self.selected_app = None
        self.status_codes = self._init_status_codes()
    
    def _init_status_codes(self):
        """Initialize comprehensive status code dictionary"""
        return {
            # Success codes
            0x9000: "Success - Normal processing",
            0x9001: "Success - Normal processing with extra information",
            
            # Warning codes (61xx)
            0x6100: "Warning - More data available (use GET RESPONSE)",
            0x6110: "Warning - More data available",
            0x6181: "Warning - Part of returned data may be corrupted",
            0x6182: "Warning - End of file reached before reading expected number of bytes",
            0x6183: "Warning - Selected file invalidated",
            0x6184: "Warning - File control information not formatted",
            0x6185: "Warning - Selected file in termination state",
            0x6186: "Warning - No input data available from sensor",
            0x6187: "Warning - At least one try left",
            0x6188: "Warning - Last try left",
            
            # Execution errors (62xx-63xx)
            0x6200: "Warning - Information added by the card (card gives information)",
            0x6281: "Warning - Part of returned data may be corrupted",
            0x6282: "Warning - End of file reached before reading Le bytes",
            0x6283: "Warning - Selected file invalidated",
            0x6284: "Warning - File control information not formatted according to 5.3.3",
            0x6285: "Warning - Selected file in termination state",
            0x6286: "Warning - No input data available from a sensor on the card",
            0x6300: "Warning - Authentication failed",
            0x6381: "Warning - File filled up by the last write",
            0x6382: "Warning - Card key not supported",
            0x6383: "Warning - Reader key not supported",
            0x6384: "Warning - Plaintext transmission not supported",
            0x6385: "Warning - Secured transmission not supported",
            0x6386: "Warning - Volatile memory is not available",
            0x6387: "Warning - Non-volatile memory is not available",
            0x6388: "Warning - Key number not valid",
            0x6389: "Warning - Key length is not correct",
            
            # Checking errors (64xx-65xx)
            0x6400: "Error - Execution error",
            0x6401: "Error - Immediate response required by the card",
            0x6481: "Error - Memory failure",
            0x6500: "Error - No information given",
            0x6501: "Error - Write problem / Memory failure / Unknown mode",
            0x6581: "Error - Memory failure",
            
            # Wrong length (6Cxx)
            0x6C00: "Error - Wrong length Le",
            
            # Functions in CLA not supported (68xx)
            0x6800: "Error - Functions in CLA not supported",
            0x6881: "Error - Logical channel not supported",
            0x6882: "Error - Secure messaging not supported",
            0x6883: "Error - Last command of the chain expected",
            0x6884: "Error - Command chaining not supported",
            
            # Command not allowed (69xx)
            0x6900: "Error - Command not allowed",
            0x6981: "Error - Command incompatible with file structure",
            0x6982: "Error - Security condition not satisfied",
            0x6983: "Error - Authentication method blocked",
            0x6984: "Error - Referenced data reversibly blocked (invalidated)",
            0x6985: "Error - Conditions of use not satisfied",
            0x6986: "Error - Command not allowed (no current EF)",
            0x6987: "Error - Expected secure messaging data objects missing",
            0x6988: "Error - Incorrect secure messaging data objects",
            
            # Wrong parameters (6Axx)
            0x6A00: "Error - Wrong parameter(s) P1-P2",
            0x6A80: "Error - Incorrect parameters in the data field",
            0x6A81: "Error - Function not supported",
            0x6A82: "Error - File or application not found",
            0x6A83: "Error - Record not found",
            0x6A84: "Error - Not enough memory space in the file",
            0x6A85: "Error - Nc inconsistent with TLV structure",
            0x6A86: "Error - Incorrect parameters P1-P2",
            0x6A87: "Error - Nc inconsistent with parameters P1-P2",
            0x6A88: "Error - Referenced data not found",
            0x6A89: "Error - File already exists",
            0x6A8A: "Error - DF name already exists",
            
            # Wrong parameters (6Bxx)
            0x6B00: "Error - Wrong parameter(s) P1-P2",
            
            # Instruction code not supported (6Dxx)
            0x6D00: "Error - Instruction code not supported or invalid",
            
            # Class not supported (6Exx)
            0x6E00: "Error - Class not supported",
            
            # Application errors (6Fxx)
            0x6F00: "Error - No precise diagnosis",
            0x6FFF: "Error - Card dead (no answer to reset)",
            
            # Proprietary/vendor specific codes
            0x9240: "MIFARE - Authentication error",
            0x9302: "MIFARE - Permission denied",
            0x9303: "MIFARE - Application not found",
            0x9310: "MIFARE - Application already exists",
            0x9320: "MIFARE - File not found", 
            0x9321: "MIFARE - File already exists",
            0x9322: "MIFARE - File is read only",
            0x9381: "MIFARE - Current authentication status does not allow the requested command",
            0x9400: "MIFARE - Length error",
            0x9401: "MIFARE - Invalid key number specified",
            0x9402: "MIFARE - Application keys are locked",
            
            # Java Card specific
            0x6999: "Java Card - Applet selection failed",
            0x6A81: "Java Card - Card locked or function not supported",
            0x9484: "Java Card - Algorithm not supported",
            0x9485: "Java Card - Invalid key for use in the specified context",
        }
    
    def decode_status(self, sw1, sw2):
        """Decode status words into human readable message"""
        status_word = (sw1 << 8) | sw2
        
        # Check exact match first
        if status_word in self.status_codes:
            return self.status_codes[status_word]
        
        # Check pattern matches
        if sw1 == 0x61:
            return f"Success - {sw2} bytes of response data can be requested"
        elif sw1 == 0x6C:
            return f"Wrong length - Expected Le={sw2:02X} ({sw2}) bytes"
        elif sw1 == 0x62:
            return f"Warning - State unchanged (SW2={sw2:02X})"
        elif sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
            tries_left = sw2 & 0x0F
            return f"Warning - Verification failed, {tries_left} tries left"
        elif sw1 == 0x63:
            return f"Warning - State changed (SW2={sw2:02X})"
        elif sw1 == 0x64:
            return f"Error - State unchanged (SW2={sw2:02X})"
        elif sw1 == 0x65:
            return f"Error - State changed (SW2={sw2:02X})"
        elif sw1 == 0x66:
            return f"Error - Security related issue (SW2={sw2:02X})"
        elif sw1 == 0x67:
            return f"Error - Wrong length (SW2={sw2:02X})"
        elif sw1 == 0x68:
            return f"Error - Functions in CLA not supported (SW2={sw2:02X})"
        elif sw1 == 0x69:
            return f"Error - Command not allowed (SW2={sw2:02X})"
        elif sw1 == 0x6A:
            return f"Error - Wrong parameters P1-P2 (SW2={sw2:02X})"
        elif sw1 == 0x6B:
            return f"Error - Wrong parameters P1-P2 (SW2={sw2:02X})"
        elif sw1 == 0x6D:
            return f"Error - Instruction not supported (SW2={sw2:02X})"
        elif sw1 == 0x6E:
            return f"Error - Class not supported (SW2={sw2:02X})"
        elif sw1 == 0x6F:
            return f"Error - No precise diagnosis (SW2={sw2:02X})"
        elif sw1 == 0x90:
            return f"Success (SW2={sw2:02X})"
        elif sw1 == 0x92:
            return f"MIFARE specific error (SW2={sw2:02X})"
        elif sw1 == 0x93:
            return f"MIFARE permission/application error (SW2={sw2:02X})"
        elif sw1 == 0x94:
            return f"MIFARE/Java Card algorithm error (SW2={sw2:02X})"
        else:
            return f"Unknown status code {sw1:02X}{sw2:02X}"
        
    def connect_to_card(self, timeout=10):
        """Connect to the Java Card"""
        try:
            available_readers = readers()
            if not available_readers:
                print("No card readers found!")
                return False
            
            # Find ACR122U or use first available
            target_reader = None
            for reader in available_readers:
                if "ACR122U" in str(reader) or "ACR122" in str(reader):
                    target_reader = reader
                    break
            
            if not target_reader:
                target_reader = available_readers[0]
            
            print(f"Using reader: {target_reader}")
            self.reader = target_reader
            
            cardtype = AnyCardType()
            cardrequest = CardRequest(timeout=timeout, cardType=cardtype, readers=[target_reader])
            
            print("Waiting for driving license card...")
            cardservice = cardrequest.waitforcard()
            cardservice.connection.connect()
            
            self.connection = cardservice.connection
            self.cardservice = cardservice
            
            # Test connection
            atr = self.connection.getATR()
            print(f"Card connected - ATR: {toHexString(atr)}")
            
            return True
            
        except Exception as e:
            print(f"Error connecting to card: {e}")
            return False
    
    def send_apdu(self, apdu_command, description=""):
        """Send APDU command with optional description"""
        try:
            if not self.connection:
                return None, None
            
            if description:
                print(f"\n{description}")
            print(f">> {toHexString(apdu_command)}")
            
            response, sw1, sw2 = self.connection.transmit(apdu_command)
            status = (sw1 << 8) | sw2
            
            print(f"<< {toHexString(response)} ({sw1:02X}{sw2:02X})")
            
            # Decode status with human readable message
            status_msg = self.decode_status(sw1, sw2)
            
            if sw1 == 0x90 and sw2 == 0x00:
                print(f"✓ {status_msg}")
            elif sw1 == 0x61:
                print(f"✓ {status_msg}")
            elif sw1 == 0x6C:
                print(f"⚠ {status_msg}")
            else:
                print(f"✗ {status_msg}")
            
            return response, (sw1, sw2)
            
        except Exception as e:
            print(f"Error sending APDU: {e}")
            return None, None
    
    def select_application(self, aid, name=""):
        """Select application by AID"""
        try:
            select_cmd = [0x00, 0xA4, 0x04, 0x00, len(aid)] + aid
            response, status = self.send_apdu(select_cmd, f"Selecting {name} application")
            
            if status and status[0] == 0x90:
                self.selected_app = name
                return True, response
            elif status and status[0] == 0x61:
                # Get response for remaining data
                get_response = [0x00, 0xC0, 0x00, 0x00, status[1]]
                response2, status2 = self.send_apdu(get_response, "Getting remaining response")
                if status2 and status2[0] == 0x90:
                    self.selected_app = name
                    return True, response + response2
            
            return False, response
            
        except Exception as e:
            print(f"Error selecting application: {e}")
            return False, None
    
    def read_file(self, file_id, max_length=256):
        """Read file by File ID"""
        try:
            # Select file
            select_file = [0x00, 0xA4, 0x02, 0x0C, 0x02] + [(file_id >> 8) & 0xFF, file_id & 0xFF]
            response, status = self.send_apdu(select_file, f"Selecting file {file_id:04X}")
            
            if not (status and (status[0] == 0x90 or status[0] == 0x61)):
                return None
            
            # Read binary data
            offset = 0
            all_data = []
            
            while offset < max_length:
                read_length = min(256, max_length - offset)
                read_cmd = [0x00, 0xB0, (offset >> 8) & 0xFF, offset & 0xFF, read_length]
                
                response, status = self.send_apdu(read_cmd, f"Reading file data at offset {offset}")
                
                if status and status[0] == 0x90:
                    all_data.extend(response)
                    if len(response) < read_length:
                        break
                    offset += len(response)
                else:
                    break
            
            return all_data
            
        except Exception as e:
            print(f"Error reading file: {e}")
            return None
    
    def parse_tlv_data(self, data):
        """Parse TLV (Tag-Length-Value) encoded data"""
        parsed = {}
        i = 0
        
        while i < len(data):
            if i >= len(data):
                break
                
            # Parse tag
            tag = data[i]
            i += 1
            
            if tag == 0x00 or tag == 0xFF:  # Skip padding
                continue
            
            if i >= len(data):
                break
                
            # Parse length
            length = data[i]
            i += 1
            
            if length & 0x80:  # Extended length
                length_bytes = length & 0x7F
                if length_bytes > 0 and i + length_bytes <= len(data):
                    length = 0
                    for j in range(length_bytes):
                        length = (length << 8) | data[i + j]
                    i += length_bytes
                else:
                    break
            
            # Parse value
            if i + length <= len(data):
                value = data[i:i + length]
                parsed[tag] = value
                i += length
            else:
                break
        
        return parsed
    
    def decode_text_field(self, data):
        """Decode text field from various encodings"""
        try:
            # Try UTF-8 first
            return data.decode('utf-8').strip('\x00').strip()
        except:
            try:
                # Try Latin-1
                return data.decode('latin-1').strip('\x00').strip()
            except:
                # Return hex if can't decode
                return toHexString(data)
    
    def probe_driving_license_apps(self):
        """Probe for known driving license applications"""
        print("\n=== Probing for Driving License Applications ===")
        
        # Known driving license AIDs from various countries/systems
        dl_applications = {
            "EU Driving License": [0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00],
            "German DL": [0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4E],
            "French DL": [0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0xAD, 0xF2],
            "Italian DL": [0xA0, 0x00, 0x00, 0x00, 0x30, 0x80, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x01, 0x01, 0x01],
            "Nordic DL": [0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0xAD, 0xF1],
            "Generic ISO7816": [0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08],
            "PKCS#15": [0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35],
            "Test Application": [0x01, 0x02, 0x03, 0x04, 0x05]
        }
        
        successful_apps = []
        
        for app_name, aid in dl_applications.items():
            print(f"\n--- Trying {app_name} ---")
            success, response = self.select_application(aid, app_name)
            
            if success:
                print(f"✓ {app_name} found!")
                successful_apps.append((app_name, aid, response))
                
                # Try to read common files
                self.read_common_dl_files()
            else:
                print(f"✗ {app_name} not available")
        
        return successful_apps
    
    def read_common_dl_files(self):
        """Read common driving license file structures"""
        print(f"\n--- Reading files from {self.selected_app} ---")
        
        # Common file IDs for driving licenses
        common_files = {
            0x0001: "Card Holder Data",
            0x0002: "Driving License Data", 
            0x0003: "Categories Data",
            0x0004: "Photo/Image Data",
            0x0005: "Signature Data",
            0x0010: "Personal Data",
            0x0011: "License Categories",
            0x0012: "Restrictions",
            0x0013: "Additional Info",
            0x2F00: "Master File",
            0x2F01: "Directory",
            0x5001: "Card Data",
            0x5002: "DL Categories",
            0x5003: "Personal Info",
            0xEF01: "Card Security",
            0xEF02: "License Info"
        }
        
        found_data = {}
        
        for file_id, description in common_files.items():
            print(f"\n--- Trying to read {description} (File ID: {file_id:04X}) ---")
            data = self.read_file(file_id, 512)
            
            if data and len(data) > 0:
                print(f"✓ Found {description}: {len(data)} bytes")
                found_data[file_id] = (description, data)
                
                # Try to parse the data
                self.analyze_file_data(description, data)
            else:
                print(f"✗ {description} not found or empty")
        
        return found_data
    
    def analyze_file_data(self, description, data):
        """Analyze and display file data"""
        print(f"\n--- Analyzing {description} ---")
        print(f"Raw data ({len(data)} bytes): {toHexString(data[:64])}{'...' if len(data) > 64 else ''}")
        
        # Try TLV parsing
        try:
            tlv_data = self.parse_tlv_data(data)
            if tlv_data:
                print("TLV Structure found:")
                for tag, value in tlv_data.items():
                    text_value = self.decode_text_field(value)
                    print(f"  Tag {tag:02X}: {text_value} ({len(value)} bytes)")
        except:
            pass
        
        # Look for text patterns
        try:
            text_data = self.decode_text_field(data)
            if any(c.isalpha() for c in text_data):
                print(f"Decoded text: {text_data}")
        except:
            pass
        
        # Look for dates (YYYYMMDD format)
        for i in range(len(data) - 7):
            try:
                date_str = ''.join([chr(b) for b in data[i:i+8] if 48 <= b <= 57])
                if len(date_str) == 8 and date_str.startswith('20'):
                    year = date_str[:4]
                    month = date_str[4:6]
                    day = date_str[6:8]
                    if 1 <= int(month) <= 12 and 1 <= int(day) <= 31:
                        print(f"Possible date found: {day}/{month}/{year}")
            except:
                continue
    
    def try_direct_commands(self):
        """Try direct APDU commands without selecting applications"""
        print("\n=== Trying Direct Commands ===")
        
        # Get card capabilities
        commands = [
            ([0x00, 0xCA, 0x9F, 0x7F, 0x00], "Get Processing Options"),
            ([0x80, 0xCA, 0x9F, 0x17, 0x00], "Get PIN Try Counter"),
            ([0x00, 0xCA, 0x00, 0x8A, 0x00], "Get Life Cycle Status"),
            ([0x00, 0xCA, 0x00, 0x5A, 0x00], "Get Application PAN"),
            ([0x00, 0xCA, 0x00, 0x50, 0x00], "Get Application Label"),
            ([0x80, 0xCA, 0x00, 0x56, 0x00], "Get Track 1 Data"),
            ([0x80, 0xCA, 0x00, 0x57, 0x00], "Get Track 2 Data"),
            ([0x00, 0xB2, 0x01, 0x0C, 0x00], "Read Record 1"),
            ([0x00, 0xB2, 0x02, 0x0C, 0x00], "Read Record 2"),
            ([0x00, 0xB2, 0x03, 0x0C, 0x00], "Read Record 3")
        ]
        
        for cmd, desc in commands:
            response, status = self.send_apdu(cmd, desc)
            if response and len(response) > 0:
                text = self.decode_text_field(response)
                print(f"  Data: {text}")
    
    def comprehensive_scan(self):
        """Perform comprehensive driving license scan"""
        print("\n=== Comprehensive Driving License Scan ===")
        
        # 1. Try to find applications
        apps = self.probe_driving_license_apps()
        
        # 2. Try direct commands
        self.try_direct_commands()
        
        # 3. If no apps found, try reading MF directly
        if not apps:
            print("\n=== No applications found, trying Master File ===")
            # Select Master File
            select_mf = [0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00]
            response, status = self.send_apdu(select_mf, "Selecting Master File")
            
            if status and status[0] == 0x90:
                # Try to read directory
                self.read_file(0x2F00, 256)
        
        print("\n=== Scan Complete ===")
    
    def disconnect(self):
        """Disconnect from card"""
        try:
            if self.connection:
                self.connection.disconnect()
                print("Card disconnected")
                self.connection = None
                self.cardservice = None
        except Exception as e:
            print(f"Error disconnecting: {e}")

def main():
    """Main function"""
    reader = DrivingLicenseReader()
    
    try:
        print("Java Card Driving License Reader")
        print("=" * 50)
        print("Place your driving license card on the reader...")
        
        if reader.connect_to_card(timeout=30):
            reader.comprehensive_scan()
        else:
            print("Failed to connect to card.")
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        reader.disconnect()

if __name__ == "__main__":
    main()
