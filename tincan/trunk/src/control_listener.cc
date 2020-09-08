/*
* ipop-project
* Copyright 2016, University of Florida
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
#include "rtc_base/net_helpers.h"
#include "control_listener.h"
#include "tincan_exception.h"
namespace tincan
{
using namespace rtc;
ControlListener::ControlListener(unique_ptr<ControlDispatch> control_dispatch):
 ctrl_dispatch_(move(control_dispatch)),
 packet_options_(DSCP_DEFAULT)
// Thread(SocketServer::CreateDefault())
{
  ctrl_thread_ = Thread::CreateWithSocketServer();
  ctrl_dispatch_->SetDispatchToListenerInf(this);
}

ControlListener::~ControlListener()
{}

void
ControlListener::ReadPacketHandler(
  AsyncPacketSocket *,
  const char * data,
  size_t len,
  const SocketAddress &,
  const int64_t& PacketTime)
{
  try {
    TincanControl ctrl(data, len);
    RTC_LOG(LS_INFO) << "Received CONTROL: " << ctrl.StyledString();
    (*ctrl_dispatch_)(ctrl);
  }
  catch(exception & e) {
    RTC_LOG(LS_WARNING) << "A control failed to execute." << "\n"
      << string(data, len) << "\n" << e.what();
  }
}
//
//IpopControllerLink interface implementation
void 
ControlListener::Deliver(
  TincanControl & ctrl_resp)
{
  std::string msg = ctrl_resp.StyledString();
  RTC_LOG(LS_INFO) << "Sending CONTROL: " << msg;
  lock_guard<mutex> lg(skt_mutex_);
  snd_socket_->SendTo(msg.c_str(), msg.length(), *ctrl_addr_, packet_options_);
}
void
ControlListener::Deliver(
  unique_ptr<TincanControl> ctrl_resp)
{
  Deliver(*ctrl_resp.get());
}
//
//DispatchtoListener interface implementation
void 
ControlListener::CreateIpopControllerLink(
  unique_ptr<SocketAddress> controller_addr)
{
  lock_guard<mutex> lg(skt_mutex_);
  ctrl_addr_ = move(controller_addr);
  SocketFactory* sf = Thread::Current()->socketserver();
  snd_socket_ = make_unique<AsyncUDPSocket>(
    sf->CreateAsyncSocket(ctrl_addr_->family(), SOCK_DGRAM));
}

/*void
ControlListener::Run()
{
	Thread* th = Thread::Current();
	const SocketAddress addr(tp.kLocalHost, tp.kUdpPort);
	//rcv_socket_ = make_unique<AsyncUDPSocket>(
          //         ctrl_thread_->socketserver()->CreateAsyncSocket(addr.family(), SOCK_DGRAM));
	rcv_socket_ = ctrl_thread_->socketserver()->CreateAsyncSocket(addr.family(), SOCK_DGRAM);
	if(!rcv_socket_)
    		throw TCEXCEPT("Failed to create control listener socket");
	rcv_socket_->Bind(addr);
	rcv_socket_->SignalReadPacket.connect(this,
    &ControlListener::ReadPacketHandler);
}*/

void
ControlListener::Run()
{
	 cout << "Setting up UDP listener\n";
 /*
  BasicPacketSocketFactory packet_factory;
  rcv_socket_.reset(packet_factory.CreateUdpSocket(
      SocketAddress(tp.kLocalHost, tp.kUdpPort), 0, 0));
*/
 const SocketAddress addr(tp.kLocalHost, tp.kUdpPort);
  SocketServer* sf = ctrl_thread_->socketserver();
  if(!sf){
          cout << "Error: No ctrl thread's socket server\n";
    return;
  }
  AsyncSocket* socket = sf->CreateAsyncSocket(addr.family(), SOCK_DGRAM);
  if(!socket){
        cout << "Error: Failed to create async socket\n";
    return;
  }
  cout << "After creating asyncsocket\n";

  //AsyncUDPSocket* rs = (AsyncUDPSocket::Create(socket, addr));
  rcv_socket_.reset(AsyncUDPSocket::Create(socket, addr));

  if (!rcv_socket_)
    throw TCEXCEPT("Failed to create control listener socket");
  RTC_LOG(LS_INFO) << "Tincan listening on " << tp.kLocalHost << " UDP port " << tp.kUdpPort;
  //rcv_socket_ = new AsyncUDPSocket::Create(socket_, addr);
  if(!rcv_socket_)
          cout << "error with createUDPsocket\n";
  rcv_socket_->SignalReadPacket.connect(this, &ControlListener::ReadPacketHandler);
  ctrl_thread_->Start();
  cout << "control thread started\n";
  //Thread::Current()->ProcessMessages(-1); //run until stopped
}

void
ControlListener::Quit()
{
  ctrl_thread_->Stop();
}  
}// namespace tincan
