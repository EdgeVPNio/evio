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
#ifndef TINCAN_TAPDEV_INF_H_
#define TINCAN_TAPDEV_INF_H_
#include "tincan_base.h"
#include "async_io.h"
#include "tap_frame.h"
#include "rtc_base/thread.h"

namespace tincan
{
using rtc::Message;
using rtc::MessageData;
using rtc::MessageHandler;

struct TapDescriptor
{
  string name;
  string ip4;
  uint32_t prefix4;
  uint32_t mtu4;
  string ip6;
  uint32_t prefix6;
  uint32_t mtu6;
};
class TapDevInf
{
public:
  enum MSG_ID
  {
    MSGID_READ,
    MSGID_WRITE,
  };
  class TapMessageData :
    public MessageData
  {
  public:
    AsyncIo * aio_;
  };

  virtual ~TapDevInf() = default;
  virtual void Open(
    const TapDescriptor & tap_desc) = 0;

  virtual void Close() = 0;

  virtual void Up() = 0;
  
  virtual void Down() = 0;

  virtual uint32_t Read(
    AsyncIo & aio_rd) = 0;

  virtual uint32_t Write(
    AsyncIo & aio_wr) = 0;

  virtual MacAddressType MacAddress() = 0;

  virtual IP4AddressType Ip4() = 0;

  virtual uint16_t Mtu() = 0;
};

}  // namespace tincan
#endif  // TINCAN_TAPDEV_H_
