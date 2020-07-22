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
#ifndef TINCAN_CONTROL_LISTENER_H_
#define TINCAN_CONTROL_LISTENER_H_
#include "tincan_base.h"
#include "webrtc/base/asyncudpsocket.h"
#include "webrtc/base/asyncpacketsocket.h"
#include "webrtc/base/logging.h"
#include "webrtc/base/sigslot.h"
#include "webrtc/base/socketaddress.h"
#include "webrtc/base/thread.h"
#include "webrtc/p2p/base/basicpacketsocketfactory.h"
#include "controller_handle.h"
#include "control_dispatch.h"
#include "tap_frame.h"

namespace tincan
{

using namespace rtc;
class ControlListener :
  public ControllerLink,
  public DispatchToListenerInf,
  public sigslot::has_slots<>,
  public Runnable
{
public:
  ControlListener(unique_ptr<ControlDispatch> control_dispatch);
  ~ControlListener();
  void ReadPacketHandler(
    AsyncPacketSocket * socket,
    const char * data,
    size_t len,
    const SocketAddress & remote_addr,
    const PacketTime & ptime);

  void Deliver(
    TincanControl & ctrl_resp) override;
  void Deliver(
    unique_ptr<TincanControl> ctrl_resp) override;
  //
  //DispatchtoListener interface implementation
  void CreateControllerLink(
    unique_ptr<SocketAddress> controller_addr
    ) override;
  ControllerLink & GetControllerLink() override
  {
    return *this;
  }
  //
  //Runnable
  void Run(Thread* thread) override;

private:
  unique_ptr<ControlDispatch> ctrl_dispatch_;
  unique_ptr<AsyncPacketSocket> rcv_socket_; //Listener for incoming Controls
  unique_ptr<AsyncUDPSocket> snd_socket_;    //Sends to Listener Controller Module
  unique_ptr<SocketAddress> ctrl_addr_;      //Address for Listener Controller Module
  PacketOptions packet_options_;
  std::mutex skt_mutex_;
};
}  // namespace tincan
#endif  // TINCAN_CONTROL_LISTENER_H_
