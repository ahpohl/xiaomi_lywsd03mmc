#include <iostream>
#include <fstream>
#include "ble.hpp"

using namespace std;

Ble::Ble(void)
{
  m_debug = false;
  m_packet = nullptr;
}

Ble::~Ble(void)
{
  delete[] m_packet;

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
  ifs.seekg (0, ifs.end);
  int length = ifs.tellg();
  ifs.seekg (0, ifs.beg);
  m_packet = new char [length];
  if (m_debug) {
    std::cout << "Reading " << length << " characters... " << endl;
  }
  ifs.read (m_packet, length);
  ifs.close();
}
