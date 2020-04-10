# Xiaomi LYWSD03MMC passive sensor readout
This program is an effort to support the Xiaomi LYWSD03MMC temperature and humidity sensor in [ESPHome](https://esphome.io/). It uses the passive method to scan for the periodically emitted ADV BLE packages and automatically decrypts the payload.

The ecryption keys have been obtained using the original [Xiaomi Home](https://play.google.com/store/apps/details?id=com.xiaomi.smarthome&hl=en) Android app and [Remote PCAP](https://play.google.com/store/apps/details?id=com.egorovandreyrm.pcapremote&hl=en). The Wireshark packet dump contains the clear text key if the root certificate has been setup correctly ([tutorial](https://egorovandreyrm.com/pcap-remote-tutorial/)). Here is the relevant part from the Wireshark packet dump:

```
packet: POST /app/device/bltbind

"data" = "{"did":"blt.3.129q4nasgeg00","token":"20c665a7ff82a5bfb5eefc36","props":[{"type":"prop","key":"bind_key","value":"dc06a798095b178767c0b74185275352"},{"type":"prop","key":"smac","value":"A4:C1:38:BF:54:5D"}]}"
```

The ``bind_key`` needs to be inserted into [ble.cpp](https://github.com/ahpohl/xiaomi_lywsd03mmc/blob/master/src/ble.cpp) in the relevant std::map (I am afraid there is no config file).

There is also a python script [mitemp_standalone.py](https://github.com/ahpohl/xiaomi_lywsd03mmc/blob/master/resources/mitemp_standalone.py) salvaged from the HomeAssistant [sensor.mitemp_bt](https://github.com/custom-components/sensor.mitemp_bt) custom component, which does the same thing as the program provided here. The as received packet is saved as ``msg.bin``, which serves as input for the C++ decryptor.

```
python resources/mitemp_standalone.py
make
./build/mitemp --file msg.bin --debug
```

# Todo
This repository serves as the basis for supporting the device in ESPHome. Development of a [xiaomi_lywsd03mmc](https://github.com/ahpohl/esphome) sensor component has been initiated. The [xiaomi_ble](https://github.com/ahpohl/esphome/tree/dev/esphome/components/xiaomi_ble) component needs to be extended with the payload decryption code given here. Additionally the configuration of the sensor needs to include the encryption key. Contributions are most welcome.

# Resources
 - ESPHome xiaomi_lywsd03mmc [support thread](https://github.com/esphome/feature-requests/issues/552)
 - [Crypto++](https://www.cryptopp.com/) library expample AES-CCM with AE
 - Remote PCAP [tutorial](https://egorovandreyrm.com/pcap-remote-tutorial/)
