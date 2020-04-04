#include <iostream>
#include <fstream>
#include <vector>
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
  vector<uint8_t> m_packet(std::istreambuf_iterator<char>(ifs), eos);
  ifs.close();
}
