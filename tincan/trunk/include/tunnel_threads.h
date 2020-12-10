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
#ifndef TINCAN_TUNNEL_THREADS_H_
#define TINCAN_TUNNEL_THREADS_H_
#include "tincan_base.h"
#include "rtc_base/thread.h"
namespace tincan
{
  class TunnelThreads {
  public:
    TunnelThreads();
    TunnelThreads(TunnelThreads& rhs) = delete;
    TunnelThreads& operator=(const TunnelThreads&) = delete;
    ~TunnelThreads();
    // <signal, network>
    std::pair<rtc::Thread*, rtc::Thread*>LinkThreads();
    rtc::Thread* TapThread();
   private:
    rtc::Thread signal_thread_;
    rtc::Thread network_thread_;
    rtc::Thread tap_thread_;
    static unsigned int num_;
  };
} // namespace tincan
#endif // TINCAN_TUNNEL_THREADS_H_
