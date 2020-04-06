# xiaomi_lywsd03mmc
This program is an effort to support the Xiaomi LYWSD03MMC temperature and humidity sensor in esphome. It uses the passive method to scan for the periodically emitted ADV Ble packages and automatically decrypts the payload.

There is also a python script salvaged from the xiaomi_mitemp HomeAssisant custom component, which does the same thing. The as received packet is saved as 'msg.bin', which serves as input for the C++ decryptor. 

'''
python resources/mitemp_standalone.py
make
./build/mitemp --file resources/msg.bin --debug
''' 

This repository serves as the basis for supporting the device in esphome. Development of a xiaomi_lywsd03mmc sensor component has been initiated. The xiaomi_ble component needs to be extended with the payload decryption code

# Resources

 - Esphome xiaomi_lywsd03mmc custom component support thread
 - HomeAssistant xiaomi_mitemp with LYWSD03MMC sensor support
 - Crypto++ library expample AES-CCM with AE
