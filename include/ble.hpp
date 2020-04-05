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
  void parsePacket(void) const;
  
private:
  bool m_debug;
  std::string m_packet;
  static const std::map<std::string, std::string> XIAOMI_TYPE;
  std::string toHex(std::string const& s) const;
};

#endif // BLE_HPP
