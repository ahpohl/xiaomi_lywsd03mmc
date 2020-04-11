#include <iostream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <map>

#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/hex.h>
#include <assert.h>

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

const map<string, string> Ble::XIAOMI_NAME = {
  {"A4:C1:38:4E:16:78", "Office"},
  {"A4:C1:38:BC:B9:B2", "Kitchen"},
  {"A4:C1:38:8C:34:B7", "Piano"},
  {"A4:C1:38:B1:CD:7F", "Sideboard"},
  {"A4:C1:38:BF:54:5D", "Bedroom"},
  {"A4:C1:38:80:C5:75", "Charlotte"},
  {"A4:C1:38:8D:D3:19", "Steffi"},
  {"A4:C1:38:6A:11:C1", "TV"}
};

Ble::Ble(void)
{
  m_debug = false;
  m_dev = nullptr;
}

Ble::~Ble(void)
{
  if (m_dev) {
    delete m_dev;
  }

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

void Ble::parsePacket(void)
{
  // check for Xiaomi service data
  size_t pos = 0;
  pos = m_packet.find("\x16\x95\xFE", 15);
  if (pos == string::npos) {
    cout << "Xiaomi service data not found" << endl;
    return;
  }
  // check for no BR/EDR + LE General discoverable mode flags
  size_t adv = 0;
  adv = m_packet.find("\x02\x01\x06", 14);
  if (adv == string::npos) {
    cout << "BR/EDR + LE general discoverable mode flags detected" << endl;
    return;
  }
  // check for BTLE packet size
  size_t packet_size = 0;
  packet_size = m_packet[2] + 3;
  if (packet_size != m_packet.length()) {
    cout << "Wrong BLE packet length (" << to_string(m_packet.length()) 
      << ")" << endl;
    return;
  }
  // check for MAC presence in message and in service data
  string mac_xiaomi(m_packet.substr(pos+8, 6));
  string mac_source(m_packet.substr(adv-7, 6));
  if (mac_xiaomi != mac_source) {
    cout << "MAC address mismatch" << endl;
    return;
  }
  // check if RSSI is valid
  int8_t rssi = m_packet.back();
  if (rssi > 0 || rssi < -127) {
    cout << "Invalid RSSI signal strength" << endl;
    return;
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
    return;
  }
  // check frame control flags, big endian format
  uint16_t framectrl = (m_packet[pos+3] << 8) | (m_packet[pos+4] & 0xFF);
  if (!(framectrl & 0x4000)) {
    cout << "No ADV payload present" << endl;
    return;
  }
  size_t payload_length;
  payload_length = (framectrl & 0x2000) ? m_packet.length()-pos-16 : 
    m_packet.length()-pos-15;
  if (payload_length < 3) {
    cout << "Invalid ADV payload length" << endl;
    return;
  }
  size_t payload_pos;
  payload_pos = (framectrl & 0x2000) ? pos+15 : pos+14;
  if (payload_length != (m_packet.substr(payload_pos+1, string::npos).length()))  {
    cout << "Invalid ADV payload start" << endl;
    return;
  }
  string cipher = m_packet.substr(payload_pos, payload_length);
  // check encrypted data flags
  if (!(framectrl & 0x0800)) {
    cout << "Plaintext ADV payload" << endl;
    return;
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
    return;
  }
  string key;
  CryptoPP::StringSource ssk(enc_key, true, new CryptoPP::HexDecoder(
    new CryptoPP::StringSink(key)));
  string iv = mac_source + m_packet.substr(pos+5, 2) 
    + m_packet.substr(pos+7, 1);

  if (m_debug) {
    string tmp;
    CryptoPP::StringSource ssk(cipher, true, new CryptoPP::HexEncoder(
      new CryptoPP::StringSink(tmp), true, 2, "")
    );
    cout << "Payload: " << tmp << endl;
  }
  string plaintext = decryptPayload(cipher, key, iv);
  if (plaintext.length() != 5) {
    throw runtime_error("Plaintext invalid length, decryption failed.");
  }
  // replace the encrypted payload with plaintext
  m_packet.replace(payload_pos, plaintext.length(), plaintext);
  if (m_debug) {
    string encoded;
    CryptoPP::StringSource ss(m_packet, true, new CryptoPP::HexEncoder(
      new CryptoPP::StringSink(encoded), true, 4, " ")
    );
    cout << "Packet : " << encoded << endl;
  }
}

string Ble::decryptPayload(string const& t_cipher, string const& t_key, 
  string const& t_iv) const
{
  string plaintext;
  int const TAG_SIZE = 4;
  string aad = "\x11";

  string enc = t_cipher.substr(0, t_cipher.length()-TAG_SIZE);
  string tag = t_cipher.substr(t_cipher.length()-TAG_SIZE);
  string payload_counter = enc.substr(enc.length()-3);
  string iv = t_iv + payload_counter;
  string cipher = enc.substr(0, enc.length()-3);
  
  if (m_debug) {
    string encoded;
    CryptoPP::StringSource ssk(t_key, true, new CryptoPP::HexEncoder(
      new CryptoPP::StringSink(encoded), true, 2, "")
    );
    cout << "Key    : " << encoded << endl;
    encoded.clear();
    CryptoPP::StringSource ssi(iv, true, new CryptoPP::HexEncoder(
      new CryptoPP::StringSink(encoded), true, 2, "")
    );
    cout << "Iv     : " << encoded << endl;
    encoded.clear();
    CryptoPP::StringSource ssc(cipher, true, new CryptoPP::HexEncoder(
      new CryptoPP::StringSink(encoded), true, 2, "")
    );
    cout << "Cipher : " << encoded << endl;
    encoded.clear();
    CryptoPP::StringSource sst(tag, true, new CryptoPP::HexEncoder(
      new CryptoPP::StringSink(encoded), true, 2, "")
    );
    cout << "Tag    : " << encoded << endl;
  }

  try {
    CryptoPP::CCM< CryptoPP::AES, TAG_SIZE >::Decryption d;
    d.SetKeyWithIV((const CryptoPP::byte*)t_key.data(), t_key.size(), 
      (const CryptoPP::byte*)iv.data(), iv.size());
    d.SpecifyDataLengths(aad.size(), cipher.size(), 0);

    CryptoPP::AuthenticatedDecryptionFilter df(d,
      new CryptoPP::StringSink(plaintext));

    // The order of the following calls are important
    df.ChannelPut(CryptoPP::AAD_CHANNEL,
      (const CryptoPP::byte*)aad.data(), aad.size());
    df.ChannelPut(CryptoPP::DEFAULT_CHANNEL,
      (const CryptoPP::byte*)cipher.data(), cipher.size());
    df.ChannelPut(CryptoPP::DEFAULT_CHANNEL,
      (const CryptoPP::byte*)tag.data(), tag.size());

    df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
    df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
  }
  catch (CryptoPP::InvalidArgument& e) {
    throw runtime_error(e.what());
  }
  catch (CryptoPP::HashVerificationFilter::HashVerificationFailed& e) {
    throw runtime_error(e.what());
  }
  if (m_debug) {
    cout << "Decrypted and verified data" << endl;
  }

  return plaintext;
}

void Ble::setDevice(void)
{
  m_dev = new device;

  size_t pos = 0;
  pos = m_packet.find("\x16\x95\xFE", 15);
  if (pos == string::npos) {
    throw runtime_error("Xiaomi service data not found");
  }
  m_dev->packet_id = (m_packet[pos+7] & 0xFF);
  string mac(m_packet.substr(pos+8, 6));
  reverse(mac.begin(), mac.end());
  CryptoPP::StringSource ssm(mac, true, new CryptoPP::HexEncoder(
    new CryptoPP::StringSink(m_dev->mac_address), true, 2, ":"));
  m_dev->rssi = m_packet.back();
  m_dev->type = XIAOMI_TYPE.at(m_packet.substr(pos+5, 2));
  m_dev->name = XIAOMI_NAME.at(m_dev->mac_address);

  size_t vpos = pos+14;  
  uint8_t vlength = m_packet[vpos+2] & 0xFF;
  uint8_t vtype = m_packet[vpos] & 0xFF;
  if (vlength == 2) {
    int16_t value = ((m_packet[vpos+4] << 8) | (m_packet[vpos+3] & 0xFF));
    switch (vtype) {
    case 0x06:
      m_dev->humidity = value / 10.0f;
      break;
    case 0x04:
      m_dev->temperature = value / 10.0f;
      break;
    default:
      cout << "Unknown payload type" << endl;
      break;
    }
  }
  if (vlength == 1 && vtype == 0x0A) {
    m_dev->battery_level = m_packet[vpos+3] & 0xFF;
  }

  if (m_debug) {
    cout << "Name   : " << m_dev->name << endl;
    cout << "Type   : " << m_dev->type << endl;
    cout << "MAC    : " << m_dev->mac_address << endl;
    cout << "Packet : " << m_dev->packet_id << endl;
    cout << "RSSI   : " << m_dev->rssi << " dBm" << endl;
    cout << "Temp   : " << fixed << setprecision(1) << m_dev->temperature
      << " °C" << endl;
    cout << "Humid  : " << m_dev->humidity << " %" << endl;
    cout << "Batt   : " << m_dev->battery_level << " %" << endl;
  }
}
