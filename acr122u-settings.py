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

def decodeATR(atr):
    # atr in HEX
    atr_printable = [0] * len(atr)
    for i in range(len(atr)):
        atr_printable[i] = format(atr[i], '#04x')[2:]
    print (f"ATR(hex): {atr_printable} len {len(atr)}")
    if len(atr) < 14:
        print ("ATR too short")
        return
    # decode tag type
    if atr[13] == 0x11:
        print ("Tag type: Mifare Classic 1K")
    elif atr[13] == 0x12:
        print ("Tag type: Mifare Classic 4K")
    elif atr[13] == 0x04:
        print ("Tag type: Mifare Ultralight")
    elif atr[13] == 0x44:
        print ("Tag type: Mifare Plus")
    elif atr[13] == 0x02:
        print ("Tag type: Mifare Mini")
    elif atr[13] == 0x28:
        print ("Tag type: Mifare DESFire")
    elif atr[13] == 0x20:
        print ("Tag type: ISO 14443-4")
    else:
        print ("Tag type: Unknown")


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

def testReader(id):
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
        decodeATR(atr)

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

    # test
    if args.status:
        testReader(0)
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
