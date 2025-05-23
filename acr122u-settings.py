#!/usr/bin/env python3
'''
ACS ACR122U NFC Reader settings view/change tool
'''
import re, argparse
from smartcard.System import readers
import datetime, sys
import smartcard.Exceptions

SETTINGS_CMD_GET = {
    "Get PICC Operating Parameter": [0xFF, 0x00, 0x50, 0x00, 0x00],
    "Set PICC Operating Parameter": [0xFF, 0x00, 0x51, 0x00, 0x00],
}

TAG_TYPE_MAP = {
    0x11: "MIFARE Classic 1K",
    0x18: "MIFARE Classic 1K (variant)",
    0x88: "MIFARE Classic 1K (variant)",
    0x08: "MIFARE Classic 2K",
    0x12: "MIFARE Classic 4K",
    0x02: "MIFARE Mini",
    0x09: "MIFARE Mini (variant)",
    0x04: "MIFARE Ultralight",
    0x03: "MIFARE Ultralight C",
    0x44: "MIFARE Plus",
    0x42: "MIFARE Plus 2K",
    0x43: "MIFARE Plus 4K",
    0x28: "MIFARE DESFire",
    0x30: "MIFARE DESFire EV1",
    0x31: "MIFARE DESFire EV2",
    0x32: "MIFARE DESFire EV3",
    0x20: "ISO 14443-4",
    0x40: "ISO 14443 Type A",
    0x41: "ISO 14443 Type B",
    0x21: "ISO 15693",
    0x01: "Topaz/Type 1",
    0x10: "FeliCa (Type 3)",
}


# Fi (Clock Rate Conversion Factor) lookup table
ta1_Fi_table = {
    0x0: (372, "Internal clock"),
    0x1: (372, "372"),
    0x2: (558, "558"), 
    0x3: (744, "744"),
    0x4: (1116, "1116"),
    0x5: (1488, "1488"),
    0x6: (1860, "1860"),
    0x7: (None, "RFU"),
    0x8: (None, "RFU"),
    0x9: (512, "512"),
    0xA: (768, "768"),
    0xB: (1024, "1024"),
    0xC: (1536, "1536"),
    0xD: (2048, "2048"),
    0xE: (None, "RFU"),
    0xF: (None, "RFU")
}

# Di (Baud Rate Adjustment Factor) lookup table
ta1_Di_table = {
    0x0: (None, "RFU"),
    0x1: (1, "1"),
    0x2: (2, "2"),
    0x3: (4, "4"),
    0x4: (8, "8"),
    0x5: (16, "16"),
    0x6: (32, "32"),
    0x7: (64, "64"),
    0x8: (12, "12"),
    0x9: (20, "20"),
    0xA: (None, "RFU"),
    0xB: (None, "RFU"),
    0xC: (None, "RFU"),
    0xD: (None, "RFU"),
    0xE: (None, "RFU"),
    0xF: (None, "RFU")
}


def load_atrlist():
    """
    Format, ATR hex starts from 3B or 3F. Ignore # comments
    <ATR hex values, space divided 2 letter HEX> sometimes .... Description
    Maybe also description
    """
    atrlist = {}
    
    atr = ""
    description = ""

    with open("atr.txt", "r") as f:
        for line in f:
            # remove comments
            if line.startswith("#"):
                continue
            # remove leading and trailing whitespace
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            # split the line into parts
            # check if the first part 3B or 3F
            if len(parts) > 0 and (parts[0] == "3B" or parts[0] == "3F"):
                # wrap up previous parts and description and add to atrlist
                if len(atr) > 0:
                    atr = atr.strip()
                    atrlist[atr] = description.strip()
                # reset atr and description
                description = ""
                atr = parts[0] + " "
                for i in range(len(parts)):
                    # is it still 2 letter hex?
                    if len(parts[i]) == 2 and re.match(r'^[0-9A-Fa-f]{2}$', parts[i]):
                        atr += parts[i] + " "
                    else:
                        # if not, rest of the line is description
                        description = " ".join(parts[i:])
                        break
            else:
                description = " ".join(parts)

    print(f"Loaded {len(atrlist)} ATRs")
    #print(f"{atrlist}")
    # add last atr and description
    return atrlist

def decodeATR(atr, atrlist):
    atr_printable = [format(b, '#04X')[2:] for b in atr]
    atr_string = " ".join(atr_printable)
    alist_keys = list(atrlist.keys())
    for key in alist_keys:
        alist_value = atrlist[key]
        # check if atr starts with key, if atr >= key
        if len(atr) >= len(key):
            # check if atr starts with key
            if atr_string.startswith(key):
                print(f"ATR match: {key} > {atrlist[key]}")
                break
        else:
            # check if key is part of atr
            if key.startswith(atr_string):
                print(f"ATR match: {key} > {atrlist[key]}")
                break

    print(f"ATR(hex): {atr_string} len {len(atr)}")
    if len(atr) < 14:
        print("ATR too short")
        return
    tag_type_code = atr[13]
    tag_type = TAG_TYPE_MAP.get(tag_type_code, "Unknown")
    print(f"Tag type: {tag_type_code:#04x} > {tag_type}")
    ta1_value = atr[2]
    ta1_fi = (ta1_value >> 4) & 0x0F
    ta1_di = ta1_value & 0x0F
    print(f"TA1: {ta1_value:#04x} > FI: {ta1_fi:#04x}, DI: {ta1_di:#04x}")
    fi_key, fi_value = ta1_Fi_table.get(ta1_fi, (None, "Unknown"))
    di_key, di_value = ta1_Di_table.get(ta1_di, (None, "Unknown"))
    fi_value = int(fi_value) if fi_value is not None and not "RFU" else None
    di_value = int(di_value) if di_value is not None and not "RFU" else None
    print(f"TA1(decode): FI={fi_value}, DI={di_value}")
    # Calculate frequency and baud rate if both values are valid
    if fi_value is not None and di_value is not None:
        frequency = fi_value
        max_frequency = 5000000  # 5 MHz typical
        actual_frequency = max_frequency / fi_value
        baud_rate = actual_frequency / di_value
        
        print(f"\nCalculated values:")
        print(f"Clock frequency: {actual_frequency/1000:.1f} kHz")
        print(f"Maximum baud rate: {baud_rate/1000:.1f} kbps")
    else:
        print(f"\nCannot calculate frequency/baud rate (RFU or invalid values)")    


def hex2str(data):
    data_printable = [0] * len(data)
    for i in range(len(data)):
        data_printable[i] = format(data[i], '#04x')[2:]
    return data_printable

# seems broken
def decodeUID(data):
  tag_type = {
    0x00: "Type 1",
    0x01: "Type 2",
    0x02: "Type 3",
    0x03: "Type 4",
    0x04: "Type 5",    
  }.get(data[0], "Unknown")

  tag_size = {
    0x00: 48,
    0x01: 96,
    0x02: 192,
    0x03: 256,
    0x04: 512,
  }.get(data[1], 0)
  print(f"Tag type: {tag_type}, size: {tag_size} bytes")

def decodeStatus(data):
    # verify first 2 bytes
    if data[0] != 0xD5 or data[1] != 0x05:
        print ("Error: Invalid status response")
        return
    # decode error
    error = {
        0x00: "No error",
        0x01: "RF buffer overflow",
        0x02: "RF field not present",
        0x03: "Protocol error",
        0x04: "Parity error",
        0x05: "CRC error",
        0x06: "Framing error",
        0x07: "Bit collision",
        0x08: "Buffer overflow",
        0x09: "Access error",
        0x0A: "Unknown command",
        0x0B: "Hardware error",
        0x0C: "Aborted",
        0x0D: "Invalid parameter",
        0x0E: "Invalid checksum",
        0x0F: "Invalid start byte",
        0x10: "Unknown error",
    }.get(data[2], "Unknown error")
    print (f"Error: {error}")
    # decode field
    field = {
        0x00: "RF field not present",
        0x01: "RF field present",
    }.get(data[3], "Unknown")
    print (f"Field: {field}")
    # decode number of targets
    nbTg = data[4]
    print (f"Number of targets: {nbTg}")
    # decode target
    if nbTg > 0:
        print ("Target(s):")
        for i in range(nbTg):
            # local target number
            localTg = data[5 + i * 5]
            print (f"  Local target number: {localTg}")
            # BrRx
            brRx = {
                0x00: "106 kbps",
                0x01: "212 kbps",
                0x02: "424 kbps",
            }.get(data[6 + i * 5], "Unknown")
            print (f"  BrRx: {brRx}")
            # BrTx
            brTx = {
                0x00: "106 kbps",
                0x01: "212 kbps",
                0x02: "424 kbps",
            }.get(data[7 + i * 5], "Unknown")
            print (f"  BrTx: {brTx}")
            # modtype
            modtype = {
                0x00: "ISO14443 or MIFARE",
                0x01: "Active mode",
                0x02: "Innovision Jewel",
                0x10: "Felica",
            }.get(data[8 + i * 5], "Unknown")
            print (f"  Modulation type: {modtype}")

def testReader(id, atrlist):
    # get all the available readers
    r = readers()
    print ("Available readers:", r)

    # select the first reader
    reader = r[0]
    print ("Using:", reader)

    # create a connection to the reader
    connection = reader.createConnection()
    if (connection):
        try:
            connection.connect()
        except smartcard.Exceptions.NoCardException:
            print ("Error: No card found")
            return None

        # get the ATR of the card
        atr = connection.getATR()
        decodeATR(atr, atrlist)

        # get NFC tag UID (seems broken?)
        #CMD = [0xFF, 0xCA, 0x00, 0x00, 0x00]
        #data, sw1, sw2 = connection.transmit(CMD)
        #if sw1 != 0x90:
        #    print ("Error: Failed to get UID")
        #    return None
        #print ("UID: ", hex2str(data))
        #decodeUID(data)

        # Get status
        CMD = [0xFF, 0x00, 0x00, 0x00, 0x02, 0xD4, 0x04]
        data, sw1, sw2 = connection.transmit(CMD)
        if sw1 != 0x90:
            print ("Error: Failed to get status")
            return None
        print ("Status: ", hex2str(data))
        # D5 05h [Err] [Field] [NbTg] [Tg] [BrRx] [BrTx] [Type] 80 90 00h
        decodeStatus(data)


        #disconnect
        connection.disconnect()

        #return
        return data
    
    else:
        print ("Failed to connect to reader")
        return None
    
def getPICC(id):
    # get all the available readers
    r = readers()
    print ("Available readers:", r)

    # select the first reader
    reader = r[0]
    print ("Using:", reader)

    # create a connection to the reader
    connection = reader.createConnection()
    if (connection):
        try:
            connection.connect()
        except smartcard.Exceptions.NoCardException:
            print ("Error: No card found")
            return None

        # get the ATR of the card
        atr = connection.getATR()
        # if atr None, card not present
        if atr is None:
            print ("Error: No card found")
            return None


        # Get PICC Operating Parameter
        CMD = SETTINGS_CMD_GET["Get PICC Operating Parameter"]
        print ("CMD: ", hex2str(CMD))
        data, sw1, sw2 = connection.transmit(CMD)
        if sw1 != 0x90:
            print ("Error: Failed to get PICC Operating Parameter")

        # print PICC Operating Parameter in hex
        print ("PICC Operating Parameter: ", hex2str(data))
        #disconnect
        connection.disconnect()

def getFirmwareVersion(id):
    # get all the available readers
    r = readers()
    print ("Available readers:", r)

    # select the first reader
    reader = r[0]
    print ("Using:", reader)

    # create a connection to the reader
    connection = reader.createConnection()
    if (connection):
        try:
            connection.connect()
        except smartcard.Exceptions.NoCardException:
            print ("Error: No card found")
            return None

        # get the ATR of the card
        atr = connection.getATR()
        # if atr None, card not present
        if atr is None:
            print ("Error: No card found")
            return None


        # Get firmware version
        CMD = [0xFF, 0x00, 0x48, 0x00, 0x00]
        print ("CMD: ", hex2str(CMD))
        data, sw1, sw2 = connection.transmit(CMD)
        # print firmware version in ASCII
        print ("Firmware version: ", ''.join(chr(i) for i in data))
        #disconnect
        connection.disconnect()
    
def main():
    argp = argparse.ArgumentParser(description='ACS ACR122U NFC Reader settings view/change tool')
    # test reader
    argp.add_argument('--status', action='store_true', help='Get status')
    argp.add_argument('--getfw', action='store_true', help='Get firmware version')
    argp.add_argument('--getpicc', action='store_true', help='Get PICC Operating Parameter')
    argp.add_argument('--setpicc', action='store_true', help='Set PICC Operating Parameter')
    # list operating parameters
    argp.add_argument('-l', '--list', action='store_true', help='List operating parameters')
    args = argp.parse_args()

    atrlist = load_atrlist()
    # test
    if args.status:
        testReader(0, atrlist)
        return
    
    # get firmware version
    if args.getfw:
        print ("Get firmware version")
        getFirmwareVersion(0)
        return

    # get picc
    if args.getpicc:
        print ("Get PICC Operating Parameter")
        data = getPICC(0)
        if data:
            print ("Data: ", hex2str(data))
        return

if __name__ == "__main__":
    main()
