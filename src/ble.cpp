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
  string iv = mac_source + m_packet.substr(pos+5, 2) + m_packet.substr(pos+7, 1);
  string plaintext = decryptPayload(cipher, key, iv);
}

string Ble::decryptPayload(string const& t_cipher, string const& t_key, 
  string const& t_iv) const
{
  string plaintext;
  int const TAG_SIZE = 4;
  string aad = "\x11";

  // Break the cipher text out into it's
  //  components: Encrypted and MAC
  string enc = t_cipher.substr(0, t_cipher.length()-TAG_SIZE);
  string tag = t_cipher.substr(t_cipher.length()-TAG_SIZE);

  try {
    CryptoPP::CCM< CryptoPP::AES, TAG_SIZE >::Decryption d;
    d.SetKeyWithIV((const CryptoPP::byte*)t_key.data(), t_key.size(), 
      (const CryptoPP::byte*)t_iv.data(), t_iv.size());
    d.SpecifyDataLengths(aad.size(), enc.size(), 0);

    CryptoPP::AuthenticatedDecryptionFilter df(d, nullptr,
      CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_BEGIN | 
      CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION
    );

    // The order of the following calls are important
    df.ChannelPut(CryptoPP::DEFAULT_CHANNEL,
      (const CryptoPP::byte*)tag.data(), tag.size());
    df.ChannelPut(CryptoPP::AAD_CHANNEL,
      (const CryptoPP::byte*)aad.data(), aad.size());
    df.ChannelPut(CryptoPP::DEFAULT_CHANNEL,
      (const CryptoPP::byte*)enc.data(), enc.size());

    df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
    df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

    // If the object does not throw, here's the only
    // opportunity to check the data's integrity
    bool b = false;
    b = df.GetLastResult();
    assert(true == b);

    // Remove data from channel
    size_t n = (size_t)-1;

    // Plain text recovered from enc.data()
    df.SetRetrievalChannel(CryptoPP::DEFAULT_CHANNEL);
    n = (size_t)df.MaxRetrievable();
    plaintext.resize(n);

    if (n > 0) {
      df.Get((CryptoPP::byte*)plaintext.data(), n);
    }

    // All is well - work with data
    if (m_debug) {
      cout << "Decrypted and Verified data. Ready for use." << endl;
    }
  }
  catch (CryptoPP::InvalidArgument& e)
  {
    cerr << "Caught InvalidArgument..." << endl;
    cerr << e.what() << endl;
  }
  catch (CryptoPP::HashVerificationFilter::HashVerificationFailed& e)
  {
    cerr << "Caught HashVerificationFailed..." << endl;
    cerr << e.what() << endl;
  }

  return plaintext;
}
