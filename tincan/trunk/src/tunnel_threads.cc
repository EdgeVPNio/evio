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

#include "tunnel_threads.h"

namespace tincan
{
unsigned int TunnelThreads::num_ = 0;
TunnelThreads::TunnelThreads():
    signal_thread_(rtc::SocketServer::CreateDefault()),
    network_thread_(rtc::SocketServer::CreateDefault()),
    tap_thread_(rtc::SocketServer::CreateDefault())
  {
    signal_thread_.SetName("SignalThread", &num_);
    signal_thread_.Start();
    network_thread_.SetName("NetworkThread", &num_);
    network_thread_.Start();
    tap_thread_.SetName("TapThread", &num_);
    tap_thread_.Start();
  }

  TunnelThreads::~TunnelThreads(){
    signal_thread_.Quit();
    network_thread_.Quit();
    tap_thread_.Quit();
  }

  std::pair<rtc::Thread*, rtc::Thread*>
  TunnelThreads::LinkThreads(){
    return make_pair(&signal_thread_, &network_thread_);
  }

  rtc::Thread*
  TunnelThreads::TapThread(){
    return &tap_thread_;
  }

} // namespace tincan
