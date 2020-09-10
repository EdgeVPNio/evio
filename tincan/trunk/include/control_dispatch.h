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
#ifndef TINCAN_CONTROL_DISPATCH_H_
#define TINCAN_CONTROL_DISPATCH_H_
#include "tincan_base.h"
#include "rtc_base/logging.h"
#include "rtc_base/log_sinks.h"
#include <map>
#include <memory>
#include <mutex>
#include "controller_handle.h"
#include "tap_frame.h"
#include "tincan_control.h"
namespace tincan
{
using rtc::FileRotatingLogSink;
using rtc::LogMessage;
class ControlDispatch
{
public:
  ControlDispatch();
  ~ControlDispatch();
  void operator () (TincanControl & control);
  void SetDispatchToTincanInf(TincanDispatchInterface * dtot);
  void SetDispatchToListenerInf(DispatchToListenerInf * dtol);

private:
  void ConfigureLogging(TincanControl & control);
  void CreateLink(TincanControl & control);
  void CreateControllerRespLink(TincanControl & control);
  void CreateTunnel(TincanControl & control);
  void Echo(TincanControl & control);
  void InjectFrame(TincanControl & control);
  void QueryLinkStats(TincanControl & control);
  void QueryTunnelInfo(TincanControl & control);
  void QueryCandidateAddressSet(TincanControl & control);
  void RemoveLink(TincanControl & control);
  void RemoveTunnel(TincanControl & control);
  void UpdateRouteTable(TincanControl & control);
  LoggingSeverity GetLogLevel(const string & log_level);
  void SendIcc(TincanControl & control);

  map<string, void (ControlDispatch::*)(TincanControl & control)>control_map_;
  DispatchToListenerInf * dtol_;
  TincanDispatchInterface * tincan_;
  ControllerLink * ctrl_link_;
  mutex disp_mutex_;
  unique_ptr<FileRotatingLogSink> log_sink_;
  class DisconnectedControllerHandle : virtual public ControllerLink {
  public:
    DisconnectedControllerHandle() {
      msg_ = "No connection to Controller exists. "
        "Create one with the set_ctrl_endpoint control operation";
    }
    virtual ~DisconnectedControllerHandle() = default;
  private:
    virtual void Deliver(
      TincanControl &) {
      RTC_LOG(LS_INFO) << msg_ << "\n";
    }
    virtual void Deliver(
      unique_ptr<TincanControl>)
    {
      RTC_LOG(LS_INFO) << msg_ << "\n";
    }
    string msg_;
  };
}; // ControlDispatch
}  // namespace tincan
#endif  // TINCAN_CONTROL_DISPATCH_H_
