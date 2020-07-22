/*
* EdgeVPNio
* Copyright 2020, University of Florida
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*/
#ifndef TINCAN_BASE_H_
#define TINCAN_BASE_H_
#include <cassert>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <array>
#include <chrono>
#include <exception>
#include <iomanip>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <stack>
#include <string>
#include <utility>
#include <unordered_map>
#include <vector>
namespace tincan
{
  using MacAddressType = std::array<uint8_t, 6>;
  using IP4AddressType = std::array<uint8_t, 4>;
  //using namespace std;
  using std::array;
  using std::chrono::milliseconds;
  using std::chrono::steady_clock;
  using std::cout;
  using std::endl;
  using std::exception;
  using std::hash;
  using std::istringstream;
  using std::list;
  using std::lock_guard;
  using std::make_pair;
  using std::make_shared;
  using std::make_unique;
  using std::map;
  using std::memcpy;
  using std::milli;
  using std::move;
  using std::mutex;
  using std::pair;
  using std::ostringstream;
  using std::out_of_range;
  using std::shared_ptr;
  using std::stack;
  using std::string;
  using std::stringstream;
  using std::unique_ptr;
  using std::unordered_map;
  using std::vector;


  struct TincanParameters
  {
  public:
    TincanParameters()
      : kVersionCheck(false), kNeedsHelp(false), kUdpPort(5800), kLinkConcurrentAIO(2)
    {}

    void ParseCmdlineArgs(
      int argc,
      char **args)
    {
      for (int i = 1; i < argc; i++)
      {
        if (strncmp(args[i], "-p=", 3) == 0)
        {
          istringstream stream(args[i]);
          stream.ignore(3);
          int port;
          char c;
          if (!(stream >> port) || stream.get(c))
          {
            kNeedsHelp = true;
            break;
          }
          else
          {
            if (port >= 0 && port <= UINT16_MAX)
            {
              kUdpPort = static_cast<uint16_t>(port);
            }
            else
            {
              kNeedsHelp = true;
              break;
            }
          }
        }
        else if (strncmp(args[i], "-i=", 3) == 0)
        {
          istringstream stream(args[i]);
          stream.ignore(3);
          int count;
          char c;
          if (!(stream >> count) || stream.get(c))
          {
            kNeedsHelp = true;
            break;
          }
          else
          {
            if (count > 32)
            {
              kLinkConcurrentAIO = 32;
            }
            else if (count < 0)
            {
              kNeedsHelp = true;
              break;
            }
            else
            {
              kLinkConcurrentAIO = static_cast<uint8_t>(count);
            }
          }
        }
        else if (strncmp(args[i], "-v", 2) == 0)
        {
          kVersionCheck = true;
        }
        else
        {
          kNeedsHelp = true;
        }
      }
    }

    static const uint16_t kTincanVerMjr = 3;
    static const uint16_t kTincanVerMnr = 0;
    static const uint16_t kTincanVerRev = 0;
    static const uint8_t kTincanControlVer = 5;
    static const uint8_t kTincanLinkVer = 1;
    static const uint16_t kMaxMtuSize = 1500;
    static const uint16_t kTapHeaderSize = 2;
    static const uint16_t kEthHeaderSize = 14;
    static const uint16_t kEthernetSize = kEthHeaderSize + kMaxMtuSize;
    static const uint16_t kTapBufferSize = kTapHeaderSize + kEthernetSize;
    static const uint8_t kFT_DTF = 0x0A;
    static const uint8_t kFT_FWD = 0x0B;
    static const uint8_t kFT_ICC = 0x0C;
    static const uint16_t kDtfMagic = 0x0A01;
    static const uint16_t kFwdMagic = 0x0B01;
    static const uint16_t kIccMagic = 0x0C01;
    static const char kCandidateDelim = ':';
    const char * const kIceUfrag = "_001EVIOICEUFRAG";
    const char * const kIcePwd = "_00000001EVIOICEPASSWORD";
    const char * const kLocalHost = "127.0.0.1";
    const char * const kLocalHost6 = "::1";
    bool kVersionCheck;
    bool kNeedsHelp;
    uint16_t kUdpPort;
    uint8_t kLinkConcurrentAIO;
  };
  ///////////////////////////////////////////////////////////////////////////////
  template<typename InputIter>
  string ByteArrayToString(
    InputIter first,
    InputIter last,
    uint32_t line_breaks = 0,
    bool use_sep = false,
    char sep = ':',
    bool use_uppercase = true)
  {
    assert(sizeof(*first) == 1);
    ostringstream oss;
    oss << std::hex << std::setfill('0');
    if(use_uppercase)
      oss << std::uppercase;
    int i = 0;
    while(first != last)
    {
      oss << std::setw(2) << static_cast<int>(*first++);
      if(use_sep && first != last)
        oss << sep;
      if(line_breaks && !(++i % line_breaks)) oss << endl;
    }
    return oss.str();
  }
  //Fixme: Doesn't handle line breaks
  template<typename OutputIter>
  size_t StringToByteArray(
    const string & src,
    OutputIter first,
    OutputIter last,
    bool sep_present = false)
  {
    assert(sizeof(*first) == 1);
    size_t count = 0;
    istringstream iss(src);
    char val[3];
    while(first != last && iss.peek() != std::istringstream::traits_type::eof())
    {
      size_t nb = 0;
      iss.get(val, 3);
      (*first++) = (uint8_t)std::stoi(val, &nb, 16);
      count++;
      if(sep_present)
        iss.get();
    }
    return count;
  }
  ///////////////////////////////////////////////////////////////////////////////
  //ArpOffset
  class ArpOffsets
  {
  public:
    ArpOffsets(uint8_t * arp_packet) :
      pkt_(arp_packet)
    {}
    uint8_t* HardwareType()
    {
      return pkt_;
    }
    uint8_t* ProtocolLen()
    {
      return &pkt_[5];
    }
    uint8_t* ArpOperation()
    {
      return &pkt_[6];
    }
    uint8_t* SourceIp()
    {
      return &pkt_[14];
    }
    uint8_t* DestinationIp()
    {
      return &pkt_[24];
    }
  private:
    uint8_t * pkt_;
  };
  ///////////////////////////////////////////////////////////////////////////////
  //IpOffsets
  class IpOffsets
  {
  public:
    IpOffsets(uint8_t * ip_packet) :
      pkt_(ip_packet)
    {}
    uint8_t* Version()
    {
      return pkt_;
    }
    uint8_t* IpHeaderLen()
    {
      return pkt_;
    }
    uint8_t* TotalLength()
    {
      return &pkt_[2];
    }
    uint8_t* Ttl()
    {
      return &pkt_[8];
    }
    uint8_t* SourceIp()
    {
      return &pkt_[12];
    }
    uint8_t* DestinationIp()
    {
      return &pkt_[16];
    }
    uint8_t* Payload()
    {
      return &pkt_[24];
    }
  private:
    uint8_t * pkt_;
  };
  ///////////////////////////////////////////////////////////////////////////////
  class EthOffsets
  {
  public:
    EthOffsets(uint8_t * eth_frame) :
      frm_(eth_frame)
    {}
    uint8_t* DestinationMac()
    {
      return frm_;
    }
    uint8_t* SourceMac()
    {
      return &frm_[6];
    }
    uint8_t* Type()
    {
      return &frm_[12];
    }
    uint8_t* Payload()
    {
      return &frm_[14];
    }
  private:
    uint8_t * frm_;
  };
} // namespace tincan
#endif // TINCAN_BASE_H_
