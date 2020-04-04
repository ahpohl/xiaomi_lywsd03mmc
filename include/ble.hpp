#ifndef BLE_HPP
#define BLE_HPP

class Ble
{
public:
  Ble(void);
  ~Ble(void);
  void setDebug(void);
  void readPacketFile(char* t_file);
  
private:
  bool m_debug;
  char* m_packet;
  
};

#endif // BLE_HPP
