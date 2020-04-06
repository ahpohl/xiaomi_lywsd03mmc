# -*- coding: utf-8 -*-
import aioblescan as aiobs
from Crypto.Cipher import AES
from threading import Thread, Lock
import asyncio
from time import sleep
import struct
import binascii

AESKEYLIST= {"A4:C1:38:4E:16:78": "e9efaa6873f9f9c87a5e75a5f814801c",
             "A4:C1:38:BC:B9:B2": "66c0f070f7394bb753e11198e3061830",
             "A4:C1:38:8C:34:B7": "cfc7cc892f4e32f7a733086cf3443cb0",
             "A4:C1:38:B1:CD:7F": "eef418daf699a0c188f3bfd17e4565d9",
             "A4:C1:38:BF:54:5D": "dc06a798095b178767c0b74185275352",
             "A4:C1:38:80:C5:75": "a1b0dbe389e0d37d0cd569a81efc555f",
             "A4:C1:38:8D:D3:19": "48403ebe2d385db8d0c187f81e62cb64",
             "A4:C1:38:6A:11:C1": "317643d6c4e31929a7a4f833bde9520a"}

class HCIdump(Thread):
    """Mimic deprecated hcidump tool."""
    
    def __init__(self, dumplist, interface=0, active=0):
        """Initiate HCIdump thread."""
        Thread.__init__(self)
        self._lock = Lock()
        self._interface = interface
        self._active = active
        self.dumplist = dumplist
        self._event_loop = None
        
    def run(self):
        """Run HCIdump thread."""
        try:
            mysocket = aiobs.create_bt_socket(self._interface)
        except OSError as error:
            print("HCIdump thread: OS error: %s", error)
        else:
            self._event_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._event_loop)
            fac = self._event_loop._create_connection_transport(mysocket, 
                aiobs.BLEScanRequester, None, None)
            conn, btctrl = self._event_loop.run_until_complete(fac)
            btctrl.process = self.process_hci_events
            btctrl.send_command(aiobs.HCI_Cmd_LE_Set_Scan_Params(
                scan_type=self._active))
            btctrl.send_scan_request()
            try:
                self._event_loop.run_forever()
            except OSError as error:
                print("HCIdump thread: OS error: %s", error)
            finally:
                btctrl.stop_scan_request()
                conn.close()
                self._event_loop.run_until_complete(asyncio.sleep(0))
                self._event_loop.close()
                print("HCIdump thread: Run finished")
                
    def join(self, timeout=3):
        """Join HCIdump thread."""
        try:
            Thread.join(self, timeout)
            print("HCIdump thread: joined")
        except AttributeError as error:
            print("HCIdump thread: %s" % error)

            
    def process_hci_events(self, data):
        """Collect HCI events."""
        with self._lock:
            self.dumplist.append(data)

class BLEScanner:
    """BLE scanner."""
    
    def __init__(self):
        self.dumpthreads = []
        self.hcidump_data = []

    def start(self):
        """Start receiving broadcasts."""
        active_scan = False
        hci_interfaces = [0]
        self.hcidump_data.clear()
        print("Spawning HCIdump thread(s).")
        for hci_int in hci_interfaces:
            dumpthread = HCIdump(dumplist=self.hcidump_data,
                interface=hci_int, active=int(active_scan is True))
            self.dumpthreads.append(dumpthread)
            print("Starting HCIdump thread for hci%d" % hci_int)
            dumpthread.start()
        print("HCIdump threads count = %d" % len(self.dumpthreads))

    def stop(self):
        """Stop HCIdump thread(s)."""
        for dumpthread in self.dumpthreads:
            dumpthread.join()
        self.dumpthreads.clear()

class xiaomi_sensor(Thread):
    """Process Xiaomi sensor ADV BLE packets"""
    
    def __init__(self):
        Thread.__init__(self)
        self._lock = Lock()
        # Structured objects for data conversions
        self.TH_STRUCT = struct.Struct("<hH")
        self.H_STRUCT = struct.Struct("<H")
        self.T_STRUCT = struct.Struct("<h")
        self.CND_STRUCT = struct.Struct("<H")
        self.ILL_STRUCT = struct.Struct("<I")
        # Xiaomi sensor types dictionary with offset for adv parser
        self.XIAOMI_TYPE_DICT = {b'\x98\x00': "HHCCJCY01",
                                 b'\xAA\x01': "LYWSDCGQ",
                                 b'\x5B\x04': "LYWSD02",
                                 b'\x47\x03': "CGG1",
                                 b'\x5D\x01': "HHCCPOT002",
                                 b'\xBC\x03': "GCLS002",
                                 b'\x5B\x05': "LYWSD03MMC",
                                 b'\x76\x05': "CGD1"}
    
    def _parse_xiaomi_value(self, hexvalue, typecode):
        """Convert value depending on its type."""
        vlength = len(hexvalue)
        if vlength == 4:
            if typecode == 0x0D:
                (temp, humi) = self.TH_STRUCT.unpack(hexvalue)
                return {"temperature": temp / 10, "humidity": humi / 10}
        if vlength == 2:
            if typecode == 0x06:
                (humi,) = self.H_STRUCT.unpack(hexvalue)
                return {"humidity": humi / 10}
            if typecode == 0x04:
                (temp,) = self.T_STRUCT.unpack(hexvalue)
                return {"temperature": temp / 10}
            if typecode == 0x09:
                (cond,) = self.CND_STRUCT.unpack(hexvalue)
                return {"conductivity": cond}
        if vlength == 1:
            if typecode == 0x0A:
                return {"battery": hexvalue[0]}
            if typecode == 0x08:
                return {"moisture": hexvalue[0]}
        if vlength == 3:
            if typecode == 0x07:
                (illum,) = self.ILL_STRUCT.unpack(hexvalue + b'\x00')
                return {"illuminance": illum}
        return None
            
    def parse_raw_message(self, data, aeskeyslist, report_unknown=False):
        """Parse the raw data."""
        if data is None:
            return None
        # check for Xiaomi service data
        xiaomi_index = data.find(b'\x16\x95\xFE', 15)
        if xiaomi_index == -1:
            return None
        # check for no BR/EDR + LE General discoverable mode flags
        adv_index = data.find(b"\x02\x01\x06", 14, 17)
        if adv_index == -1:
            return None
        # check for BTLE msg size
        msg_length = data[2] + 3
        if msg_length != len(data):
            return None
        # check for MAC presence in message and in service data
        xiaomi_mac_reversed = data[xiaomi_index + 8:xiaomi_index + 14]
        source_mac_reversed = data[adv_index - 7:adv_index - 1]
        if xiaomi_mac_reversed != source_mac_reversed:
            return None
        # check if RSSI is valid
        (rssi,) = struct.unpack("<b", data[msg_length - 1:msg_length])
        if not 0 >= rssi >= -127:
            return None
        try:
            sensor_type = self.XIAOMI_TYPE_DICT[
                data[xiaomi_index + 5:xiaomi_index + 7]]
        except KeyError:
            if report_unknown:
                print("BLE ADV from UNKNOWN: RSSI: %s, MAC: %s, ADV: %s" % (
                    rssi,
                    ''.join('{:02X}'.format(x) for x in xiaomi_mac_reversed[::-1]),
                    data.hex()))
            return None
        # frame control bits
        framectrl, = struct.unpack('>H', data[xiaomi_index + 3:xiaomi_index + 5])
        # check data is present
        if not (framectrl & 0x4000):
            return None
        xdata_length = 0
        xdata_point = 0
        # check capability byte present
        if framectrl & 0x2000:
            xdata_length = -1
            xdata_point = 1
        # xiaomi data length = message length
        #     -all bytes before XiaomiUUID
        #     -3 bytes Xiaomi UUID + ADtype
        #     -1 byte rssi
        #     -3+1 bytes sensor type
        #     -1 byte packet_id
        #     -6 bytes MAC
        #     - capability byte offset
        xdata_length += msg_length - xiaomi_index - 15
        if xdata_length < 3:
            return None
        xdata_point += xiaomi_index + 14
        # check if xiaomi data start and length is valid
        if xdata_length != len(data[xdata_point:-1]):
            return None
        # check encrypted data flags
        with open("msg.bin", "wb") as fh:
            fh.write(data)
        if framectrl & 0x0800:
            # try to find encryption key for current device
            try:
                key = AESKEYLIST[
                    ":".join("{:02X}".format(x) for x in xiaomi_mac_reversed[::-1])]
                key = binascii.a2b_hex(key)
            except KeyError:
                # no encryption key found
                return None
            nonce = b"".join([xiaomi_mac_reversed,
                              data[xiaomi_index + 5:xiaomi_index + 7],
                              data[xiaomi_index + 7:xiaomi_index + 8]])
            decrypted_payload = self._decrypt_payload(
                data[xdata_point:msg_length-1], key, nonce)
            if decrypted_payload is None:
                print("MAC address: %s\nkey: %s\n" % (
                    "".join("{:02X}".format(x) for x in xiaomi_mac_reversed[::-1]),
                    binascii.b2a_hex(key).decode()))
                return None
            # replace cipher with decrypted data
            msg_length -= len(data[xdata_point:msg_length-1])
            data = b"".join((data[:xdata_point], decrypted_payload, data[-1:]))
            msg_length += len(decrypted_payload)
        packet_id = data[xiaomi_index + 7]
        result = {
            "rssi": rssi,
            "mac": ''.join('{:02X}'.format(x) for x in xiaomi_mac_reversed[::-1]),
            "type": sensor_type,
            "packet": packet_id,
        }
        # loop through xiaomi payload
        # assume that the data may have several values of different types,
        # although I did not notice this behavior with my LYWSDCGQ sensors
        while True:
            xvalue_typecode = data[xdata_point]
            try:
                xvalue_length = data[xdata_point + 2]
            except ValueError as error:
                print("xvalue_length conv. error: %s" % error)
                print("xdata_point: %s" % xdata_point)
                print("data: %s", data.hex())
                result = {}
                break
            except IndexError as error:
                print("Wrong xdata_point: %s" % error)
                print("xdata_point: %s" % xdata_point)
                print("data: %s" % data.hex())
                result = {}
                break
            xnext_point = xdata_point + 3 + xvalue_length
            xvalue = data[xdata_point + 3:xnext_point]
            res = self._parse_xiaomi_value(xvalue, xvalue_typecode)
            if res:
                result.update(res)
            if xnext_point > msg_length - 3:
                break
            xdata_point = xnext_point
        return result
    
    def _decrypt_payload(self, encrypted_payload, key, nonce):
        """Decrypt payload."""
        aad = b"\x11"
        token = encrypted_payload[-4:]
        payload_counter = encrypted_payload[-7:-4]
        nonce = b"".join([nonce, payload_counter])
        cipherpayload = encrypted_payload[:-7]
        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        cipher.update(aad)
        plaindata = None
        try:
            plaindata = cipher.decrypt_and_verify(cipherpayload, token)
        except ValueError as error:
            print("Decryption failed: %s" % error)
            print("token: %s" % token.hex())
            print("nonce: %s" % nonce.hex())
            print("encrypted_payload: %s" % encrypted_payload.hex())
            print("cipherpayload: %s" % cipherpayload.hex())
            return None
        #print("key: %s" % key.hex().upper())
        #print("nonce: %s" % nonce.hex().upper())
        #print("encrypted_payload: %s" % encrypted_payload.hex().upper())
        #print("cipherpayload: %s" % cipherpayload.hex().upper())
        #print("token: %s" % token.hex().upper())
        #print("plaintext: %s\n" % plaindata.hex().upper())
        return plaindata
    
    def run(self, interval=10):
        """Run Xiaomi thread"""
        def lpacket(mac, packet=None):
            """Last_packet static storage."""
            if packet is not None:
                lpacket.cntr[mac] = packet
            else:
                try:
                    cntr = lpacket.cntr[mac]
                except KeyError:
                    cntr = None
                return cntr
        lpacket.cntr = {}
        scanner = BLEScanner()
        scanner.start()
        while True:
            sleep(interval)
            with self._lock:
                hcidump_raw = [*scanner.hcidump_data]
                scanner.hcidump_data.clear()
            #print(len(hcidump_raw))
            for msg in hcidump_raw:
                data = self.parse_raw_message(msg, AESKEYLIST)
                if data and "mac" in data:
                    # ignore duplicated message
                    packet = data["packet"]
                    prev_packet = lpacket(mac=data["mac"])
                    if prev_packet == packet:
                        continue
                    lpacket(data["mac"], packet)
                    print(data)
    
    def join(self):
        """Join Xiaomi thread."""
        try:
            Thread.join(self)
            print("Xiaomi thread: joined")
        except AttributeError as error:
            print("Xiaomi thread: %s" % error)
    
if __name__ == '__main__':
    sensor = xiaomi_sensor()
    sensor.start()
