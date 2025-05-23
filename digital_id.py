#!/usr/bin/env python3
"""
(AI written) ACR122U Digital ID Reader
Digital ID Reader using ACR122U and pyscard library
Retrieves information from contactless smart cards (digital IDs)
"""

from smartcard.System import readers
from smartcard.util import toHexString, toBytes
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import CardRequestTimeoutException, NoCardException
import time

class DigitalIDReader:
    def __init__(self):
        self.connection = None
        self.reader = None
        self.cardservice = None
        
    def list_readers(self):
        """List all available card readers"""
        try:
            available_readers = readers()
            print("Available readers:")
            for i, reader in enumerate(available_readers):
                print(f"  {i}: {reader}")
            return available_readers
        except Exception as e:
            print(f"Error listing readers: {e}")
            return []
    
    def connect_to_card(self, timeout=10):
        """Connect to a card using ACR122U reader"""
        try:
            # Get available readers
            available_readers = readers()
            
            if not available_readers:
                print("No card readers found!")
                return False
            
            # Look for ACR122U specifically
            acr122u_reader = None
            for reader in available_readers:
                if "ACR122U" in str(reader) or "ACR122" in str(reader):
                    acr122u_reader = reader
                    break
            
            if not acr122u_reader:
                print("ACR122U reader not found. Using first available reader.")
                acr122u_reader = available_readers[0]
            
            print(f"Using reader: {acr122u_reader}")
            self.reader = acr122u_reader
            
            # Request any card type
            cardtype = AnyCardType()
            cardrequest = CardRequest(timeout=timeout, cardType=cardtype, readers=[acr122u_reader])
            
            print("Waiting for card...")
            cardservice = cardrequest.waitforcard()
            
            # Connect to the card
            cardservice.connection.connect()
            self.connection = cardservice.connection
            self.cardservice = cardservice  # Store the service as well
            
            print("Card connected successfully!")
            print(f"Connection established: {self.connection}")
            
            # Test the connection immediately
            try:
                atr = self.connection.getATR()
                print(f"Connection test - ATR: {toHexString(atr)}")
            except Exception as e:
                print(f"Connection test failed: {e}")
                return False
            
            return True
            
        except CardRequestTimeoutException:
            print("Timeout: No card detected within the specified time.")
            return False
        except Exception as e:
            print(f"Error connecting to card: {e}")
            return False
    
    def send_apdu(self, apdu_command):
        """Send APDU command to the card"""
        try:
            if not self.connection:
                print("No card connection available")
                return None, None
            
            # Check if connection is still active
            if not hasattr(self.connection, 'transmit'):
                print("Connection is not active")
                return None, None
            
            print(f"Sending APDU: {toHexString(apdu_command)}")
            response, sw1, sw2 = self.connection.transmit(apdu_command)
            
            print(f"Response: {toHexString(response)}")
            print(f"Status: SW1=0x{sw1:02X}, SW2=0x{sw2:02X}")
            
            return response, (sw1, sw2)
            
        except Exception as e:
            print(f"Error sending APDU: {e}")
            return None, None
    
    def get_card_atr(self):
        """Get the Answer To Reset (ATR) from the card"""
        try:
            if self.connection:
                atr = self.connection.getATR()
                print(f"Card ATR: {toHexString(atr)}")
                return atr
            return None
        except Exception as e:
            print(f"Error getting ATR: {e}")
            return None
    
    def read_card_uid(self):
        """Read card UID (for MIFARE cards)"""
        try:
            # APDU command to get card UID
            # This works for many contactless cards
            get_uid_cmd = [0xFF, 0xCA, 0x00, 0x00, 0x00]
            response, status = self.send_apdu(get_uid_cmd)
            
            if status and status[0] == 0x90 and status[1] == 0x00:
                uid = toHexString(response)
                print(f"Card UID: {uid}")
                return response
            else:
                print("Failed to read UID")
                return None
                
        except Exception as e:
            print(f"Error reading UID: {e}")
            return None
    
    def select_application(self, aid):
        """Select application by AID (Application Identifier)"""
        try:
            # SELECT command (CLA=00, INS=A4, P1=04, P2=00)
            select_cmd = [0x00, 0xA4, 0x04, 0x00, len(aid)] + aid
            response, status = self.send_apdu(select_cmd)
            
            if status and status[0] == 0x90:
                print("Application selected successfully")
                return True
            else:
                print(f"Failed to select application. Status: {status}")
                return False
                
        except Exception as e:
            print(f"Error selecting application: {e}")
            return False
    
    def read_binary_data(self, offset=0, length=0):
        """Read binary data from the card"""
        try:
            # READ BINARY command (CLA=00, INS=B0)
            if length == 0:
                read_cmd = [0x00, 0xB0, (offset >> 8) & 0xFF, offset & 0xFF, 0x00]
            else:
                read_cmd = [0x00, 0xB0, (offset >> 8) & 0xFF, offset & 0xFF, length]
            
            response, status = self.send_apdu(read_cmd)
            
            if status and status[0] == 0x90:
                print(f"Binary data read successfully: {toHexString(response)}")
                return response
            else:
                print(f"Failed to read binary data. Status: {status}")
                return None
                
        except Exception as e:
            print(f"Error reading binary data: {e}")
            return None
    
    def probe_common_applications(self):
        """Probe for common digital ID applications"""
        print("\n=== Probing for common applications ===")
        
        # Common AIDs for digital ID cards
        common_aids = {
            "eID (Belgian)": [0xA0, 0x00, 0x00, 0x01, 0x77, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35],
            "German eID": [0xE8, 0x28, 0xBD, 0x08, 0x0F],
            "MRTD (Passport)": [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01],
            "PIV (US Gov)": [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00],
            "OpenPGP": [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
        }
        
        for app_name, aid in common_aids.items():
            print(f"\nTrying {app_name}...")
            if self.select_application(aid):
                print(f"✓ {app_name} application found!")
                # Try to read some basic data
                self.read_binary_data(0, 16)
            else:
                print(f"✗ {app_name} not found")
    
    def comprehensive_card_info(self):
        """Get comprehensive information about the card"""
        print("\n=== Comprehensive Card Information ===")
        
        # Get ATR
        atr = self.get_card_atr()
        
        # Get UID
        uid = self.read_card_uid()
        
        # Probe applications
        self.probe_common_applications()
        
        # Try some basic commands
        print("\n=== Basic Card Commands ===")
        
        # Get card version (works on some cards)
        version_cmd = [0xFF, 0x00, 0x48, 0x00, 0x00]
        self.send_apdu(version_cmd)
        
        # Get firmware version (ACR122U specific)
        firmware_cmd = [0xFF, 0x00, 0x48, 0x00, 0x00]
        self.send_apdu(firmware_cmd)
    
    def disconnect(self):
        """Disconnect from the card"""
        try:
            if self.connection:
                self.connection.disconnect()
                print("Card disconnected")
                self.connection = None
                self.cardservice = None
        except Exception as e:
            print(f"Error disconnecting: {e}")

def main():
    """Main function to demonstrate digital ID reading"""
    reader = DigitalIDReader()
    
    try:
        # List available readers
        available_readers = reader.list_readers()
        
        if not available_readers:
            print("No card readers found. Please ensure ACR122U is connected.")
            return
        
        # Connect to card
        if reader.connect_to_card(timeout=30):
            # Get comprehensive card information
            reader.comprehensive_card_info()
        else:
            print("Failed to connect to card. Please place a card on the reader.")
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    
    except Exception as e:
        print(f"Unexpected error: {e}")
    
    finally:
        # Always disconnect
        reader.disconnect()

if __name__ == "__main__":
    print("Digital ID Reader for ACR122U")
    print("=" * 40)
    print("Place your digital ID card on the reader when prompted...")
    print()
    
    main()