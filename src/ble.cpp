#include <iostream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <map>
#include <cryptopp/hex.h>
#include "ble.hpp"

using namespace std;

const map<string, string> Ble::XIAOMI_TYPE = {
  {"\x98\x00", "HHCCJCY01"},
  {"\xAA\x01", "LYWSDCGQ"},
  {"\x5B\x04", "LYWSD02"},
  {"\x47\x03", "CGG1"},
  {"\x5D\x01", "HHCCPOT002"},
  {"\xBC\x03", "GCLS002"},
  {"\x5B\x05", "LYWSD03MMC"},
  {"\x76\x05", "CGD1"}  
};

Ble::Ble(void)
{
  m_debug = false;
}

Ble::~Ble(void)
{
  if (m_debug) {
    cout << "Ble destructor method called" << endl;
  }
}

void Ble::setDebug(void)
{
  m_debug = true;
}

void Ble::readPacketFile(char* t_file)
{
  ifstream ifs;
  ifs.exceptions(ifstream::failbit | ifstream::badbit);
  try {
    ifs.open(t_file, ios::binary | ios::in); 
  }
  catch (ifstream::failure const& e) {
    cerr << "Exception opening file: " << e.what() << endl;
  }
  if (m_debug) {
    ifs.seekg (0, ifs.end);
    int length = ifs.tellg();
    ifs.seekg (0, ifs.beg);
    std::cout << "Reading " << length << " characters... " << endl;
  }
  istreambuf_iterator<char> eos;
  m_packet.assign(std::istreambuf_iterator<char>(ifs), eos);
  ifs.close();
}

void Ble::parsePacket(void) const
{
  // check for Xiaomi service data
  size_t pos = 0;
  pos = m_packet.find("\x16\x95\xFE", 15);
  if (pos == string::npos) {
    throw runtime_error("Xiaomi service data not found");
  }
  // check for no BR/EDR + LE General discoverable mode flags
  size_t adv = 0;
  adv = m_packet.find("\x02\x01\x06", 14);
  if (adv == string::npos) {
    throw runtime_error("BR/EDR + LE general discoverable mode flags detected");
  }
  // check for BTLE packet size
  size_t packet_size = 0;
  packet_size = m_packet[2] + 3;
  if (packet_size != m_packet.length()) {
    throw runtime_error(string("Wrong BLE packet length (") + 
      to_string(m_packet.length()) + ")");
  }
  // check for MAC presence in message and in service data
  string mac_xiaomi(m_packet.substr(pos+8, 6));
  string mac_source(m_packet.substr(adv-7, 6));
  if (mac_xiaomi != mac_source) {
    throw runtime_error("MAC address mismatch");
  }
  // check if RSSI is valid
  int8_t rssi = m_packet.back();
  if (rssi > 0 || rssi < -127) {
    throw runtime_error("Invalid RSSI signal strength");
  }
  // get sensor type from dictionary, report unknown
  string sensor_type("Hello World");
  try {
    sensor_type = XIAOMI_TYPE.at(m_packet.substr(pos+5, 2));
  }
  catch (exception const& e) {
    string encoded;
    reverse(mac_xiaomi.begin(), mac_xiaomi.end());
    CryptoPP::StringSource ss(mac_xiaomi, true, new CryptoPP::HexEncoder(
        new CryptoPP::StringSink(encoded))
    );
    cout << "BLE ADV from UNKNOWN: RSSI: " << to_string(rssi) 
      << " dBm, MAC: " << encoded << endl;
    throw runtime_error(e.what());
  }
}
