#include <iostream>
#include <fstream>
#include "ble.hpp"

using namespace std;

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
  string m_packet(std::istreambuf_iterator<char>(ifs), eos);
  ifs.close();
}

void Ble::parsePacket(void) const
{
  size_t pos = 0;
  string xiaomi_mitemp = "\x16\x95\xFE";
  //TODO: m_packet is an empty string
  pos = m_packet.find(xiaomi_mitemp);
  if (pos == string::npos) {
    throw runtime_error("Xiaomi service data not found");
  }
  cout << pos << endl;
}
