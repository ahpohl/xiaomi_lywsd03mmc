# xiaomi_lywsd03mmc
This program is an effort to support the Xiaomi LYWSD03MMC temperature and humidity sensor in [ESPHome](https://esphome.io/). It uses the passive method to scan for the periodically emitted ADV BLE packages and automatically decrypts the payload.

There is also a python script salvaged from the HomeAssistant [sensor.mitemp_bt](https://github.com/custom-components/sensor.mitemp_bt) custom component, which does the same thing as the program provided here. The as received packet is saved as ``msg.bin``, which serves as input for the C++ decryptor. 

```
python resources/mitemp_standalone.py
make
./build/mitemp --file resources/msg.bin --debug
```

This repository serves as the basis for supporting the device in ESPHome. Development of a [xiaomi_lywsd03mmc](https://github.com/ahpohl/esphome) sensor component has been initiated. The [xiaomi_ble](https://github.com/esphome/esphome/tree/dev/esphome/components/xiaomi_ble) component needs to be extended with the payload decryption code given here.

# Resources

 - ESPHome [xiaomi_lywsd03mmc](https://github.com/esphome/feature-requests/issues/552) support thread
 - [Crypto++](https://www.cryptopp.com/) library expample AES-CCM with AE
