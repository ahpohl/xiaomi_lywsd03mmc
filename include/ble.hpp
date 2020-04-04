#ifndef BLE_HPP
#define BLE_HPP

#include <vector>

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
  
};

#endif // BLE_HPP
