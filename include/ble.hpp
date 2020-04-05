#ifndef BLE_HPP
#define BLE_HPP

#include <map>

class Ble
{
public:
  Ble(void);
  ~Ble(void);
  void setDebug(void);
  void readPacketFile(char* t_file);
  void parsePacket(void);
  int getTemperature(void) const;
  int getHumidity(void) const;
  int getBatteryLevel(void) const;
  
private:
  bool m_debug;
  std::string m_packet;
  std::string m_plaintext;
  static const std::map<std::string, std::string> XIAOMI_TYPE;
  static const std::map<std::string, std::string> XIAOMI_KEYS;
  std::string decryptPayload(std::string const& t_cipher,
    std::string const& t_key, std::string const& t_iv) const;
};

#endif // BLE_HPP
