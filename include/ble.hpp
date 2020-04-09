#ifndef BLE_HPP
#define BLE_HPP

#include <map>

typedef struct {
    size_t packet_id;
    std::string name;
    std::string type;
    std::string mac_address;
    int rssi;
    double temperature;
    double humidity;
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
  void setDevice(void);

private:
  bool m_debug;
  std::string m_packet;
  device* m_dev;

  std::string decryptPayload(std::string const& t_cipher,
    std::string const& t_key, std::string const& t_iv) const;

  static const std::map<std::string, std::string> XIAOMI_NAME;
  static const std::map<std::string, std::string> XIAOMI_TYPE;
  static const std::map<std::string, std::string> XIAOMI_KEYS;
};

#endif // BLE_HPP
