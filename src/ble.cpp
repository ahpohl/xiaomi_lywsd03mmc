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

const map<string, string> Ble::XIAOMI_KEYS = {
  {"A4:C1:38:4E:16:78", "e9efaa6873f9f9c87a5e75a5f814801c"},
  {"A4:C1:38:BC:B9:B2", "66c0f070f7394bb753e11198e3061830"},
  {"A4:C1:38:8C:34:B7", "cfc7cc892f4e32f7a733086cf3443cb0"},
  {"A4:C1:38:B1:CD:7F", "eef418daf699a0c188f3bfd17e4565d9"},
  {"A4:C1:38:BF:54:5D", "dc06a798095b178767c0b74185275352"},
  {"A4:C1:38:80:C5:75", "a1b0dbe389e0d37d0cd569a81efc555f"},
  {"A4:C1:38:8D:D3:19", "48403ebe2d385db8d0c187f81e62cb64"},
  {"A4:C1:38:6A:11:C1", "317643d6c4e31929a7a4f833bde9520a"}
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
  // check sensor type, report unknown
  string sensor_type;
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
  // check frame control flags, big endian format
  uint16_t framectrl = (m_packet[pos+3] << 8) | (m_packet[pos+4] & 0xFF);
  if (!(framectrl & 0x4000)) {
    throw runtime_error("No ADV payload present");
  }
  size_t payload_length;
  payload_length = (framectrl & 0x2000) ? m_packet.length()-pos-16 : 
    m_packet.length()-pos-15;
  if (payload_length < 3) {
    throw runtime_error("Invalid ADV payload length");
  }
  size_t payload_pos;
  payload_pos = (framectrl & 0x2000) ? pos+15 : pos+14;
  if (payload_length != (m_packet.substr(payload_pos+1, string::npos).length()))  {
    throw runtime_error("Invalid ADV payload start");
  }
  string cipher = m_packet.substr(payload_pos, payload_length);
  // check encrypted data flags
  if (!(framectrl & 0x0800)) {
    throw runtime_error("Plaintext ADV payload");
  }
  // lookup encryption key
  string enc_mac;
  reverse(mac_xiaomi.begin(), mac_xiaomi.end());
  CryptoPP::StringSource ssm(mac_xiaomi, true, new CryptoPP::HexEncoder(
    new CryptoPP::StringSink(enc_mac), true, 2, ":")
  );
  string enc_key;
  try {
    enc_key = XIAOMI_KEYS.at(enc_mac);
  }
  catch (exception const& e) {
    cout << "MAC address " << enc_mac << ": encryption key unknown" << endl;
    throw runtime_error(e.what());
  }
  string key;
  CryptoPP::StringSource ssk(enc_key, true, new CryptoPP::HexDecoder(
    new CryptoPP::StringSink(key)));
  string packet_id = m_packet[pos+7];
  string iv = mac_source + m_packet.substr(pos+5, 2) + m_packet[pos+7];
  string plaintext = decryptPayload(cipher, key, iv);
}

string Ble::decryptPaylod(string const& cipher, string const& key, 
  string const& iv) const
{
  string plaintext;


  return plaintext;
}
