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
#ifndef TINCAN_TAPDEV_LNX_H_
#define TINCAN_TAPDEV_LNX_H_
#if defined (_TNC_LINUX)

#include "async_io.h"
#include "tapdev_inf.h"
#include "tincan_base.h"

#include "rtc_base/logging.h"
#include "rtc_base/thread.h"
#include "rtc_base/third_party/sigslot/sigslot.h"

#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <net/route.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace tincan
{

namespace linux
{
using rtc::Message;
using rtc::MessageData;
using rtc::MessageHandler;
using rtc::SocketServer;
class TapDevLnx :
  public TapDevInf,
  public MessageHandler
{
public:
  TapDevLnx();
  virtual ~TapDevLnx();
  sigslot::signal1<AsyncIo *> read_completion_;
  sigslot::signal1<AsyncIo *> write_completion_;
  void Open(
    const TapDescriptor & tap_desc) override;
  void Close() override;
  uint32_t Read(AsyncIo& aio_rd) override;
  uint32_t Write(AsyncIo& aio_wr) override;
  uint16_t Mtu() override;
  void Up() override;
  void Down() override;
  MacAddressType MacAddress() override;
  IP4AddressType Ip4() override;
protected:
  void OnMessage(Message * msg) override;
private:
  unique_ptr<rtc::Thread> reader_;
  unique_ptr<rtc::Thread> writer_;
  struct ifreq ifr_;
  int fd_;
  IP4AddressType ip4_;
  MacAddressType mac_;
  //uint16_t mtu4_;
  bool is_good_;
  void SetFlags(short a, short b);
  void PlenToIpv4Mask(unsigned int a, struct sockaddr *b);
};
}
}
#endif //_TNC_LINUX
#endif 
