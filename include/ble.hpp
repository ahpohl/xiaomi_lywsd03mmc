#ifndef BLE_HPP
#define BLE_HPP

#include <map>

typedef struct {
    std::string name;
    std::string type;
    std::string mac;
    double temperature;
    int humidity;
    int battery_level;
} device;

class Ble
{
public:
  Ble(void);
  ~Ble(void);
  void setDebug(void);
  void readPacketFile(char* t_file);
  void parsePacket(void);
  void getDevice(void);
  
private:
  bool m_debug;
  std::string m_packet;
  device* m_device;

  std::string decryptPayload(std::string const& t_cipher,
    std::string const& t_key, std::string const& t_iv) const;
  void setDevice(void);

  static const std::map<std::string, std::string> XIAOMI_NAME;
  static const std::map<std::string, std::string> XIAOMI_TYPE;
  static const std::map<std::string, std::string> XIAOMI_KEYS;
};

#endif // BLE_HPP
