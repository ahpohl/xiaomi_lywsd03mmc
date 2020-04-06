#include <iostream>
#include <getopt.h>
#include "ble.hpp"

using namespace std;

int main(int argc, char* argv[])
{
  bool debug = false;
  bool help = false;
  char* packet_file = nullptr;

  const struct option longOpts[] = {
    { "help", no_argument, nullptr, 'h' },
    { "debug", no_argument, nullptr, 'D' },
    { "file", required_argument, nullptr, 'f' },
    { nullptr, 0, nullptr, 0 }
  };

  const char* const optString = "hDf:";
  int opt = 0;
  int longIndex = 0;

  do {
    opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
    switch (opt) {
    case 'h':
      help = true;
      break;
    case 'D':
      debug = true;
      break;
    case 'f':
      packet_file = optarg;
      break;
    default:
      break;
    }

  } while (opt != -1);

  if (help)
  {
    cout << "Decrypt Xiaomi Bluetooth LE ADV Packets" << endl;
    cout << endl << "Usage: " << argv[0] << " [options]" << endl << endl;
    cout << "\
  -h --help              Show help message\n\
  -D --debug             Show debug messages\n\
  -f --file [NAME]       File with BLE ADV packet"
    << endl << endl;
    return 0;
  }

  Ble myBle;
  if (debug) {
    myBle.setDebug();
  }
  myBle.readPacketFile(packet_file);
  myBle.parsePacket();
  myBle.setDevice();

  return 0;
}
