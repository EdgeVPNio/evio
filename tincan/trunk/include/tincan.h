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
#ifndef TINCAN_TINCAN_H_
#define TINCAN_TINCAN_H_
#include "tincan_base.h"
#include "rtc_base/event.h"
#include "control_listener.h"
#include "control_dispatch.h"
#include "single_link_tunnel.h"

namespace tincan {
class Tincan :
  public TincanDispatchInterface,
  public sigslot::has_slots<>
{
public:
  Tincan();
  ~Tincan();
  //
  //TincanDispatchInterface interface

  void CreateVlink(
    const Json::Value & link_desc,
    const TincanControl & control) override;

  void CreateTunnel(
    const Json::Value & tnl_desc,
    Json::Value & tnl_info) override;
  
  void InjectFrame(
    const Json::Value & frame_desc) override;

  void QueryLinkStats(
    const Json::Value & link_desc,
    Json::Value & node_info) override;

  void QueryTunnelInfo(
    const Json::Value & tnl_desc,
    Json::Value & node_info) override;

  void RemoveTunnel(
    const Json::Value & tnl_desc) override;

  void RemoveVlink(
    const Json::Value & link_desc) override;

  void SendIcc(
    const Json::Value & icc_desc) override;

  void SetControllerLink(
    ControllerLink * ctrl_handle) override;

  void UpdateRouteTable(
    const Json::Value & rts_desc) override;

  void QueryLinkCas(
    const Json::Value & link_desc,
    Json::Value & cas_info) override;
//
  void OnLocalCasUpdated(
    string link_id,
    string lcas);

  void Run();
private:
  bool IsTunnelExisit(
    const string & tnl_id);

  BasicTunnel & TunnelFromId(
    const string & tnl_id);

  void OnStop();
  void Shutdown();
  //TODO:Code cleanup
#if defined(_TNC_WIN)
  static BOOL __stdcall ControlHandler(
    DWORD CtrlType);
#endif // _TNC_WIN

  vector<unique_ptr<BasicTunnel>> tunnels_;
  ControllerLink * ctrl_link_;
  map<string, unique_ptr<TincanControl>> inprogess_controls_;
  shared_ptr<ControlListener> ctrl_listener_; //must be destroyed before ctl_thread
  static Tincan * self_;
  std::mutex tunnels_mutex_;
  std::mutex inprogess_controls_mutex_;
  rtc::Event exit_event_;

};
} //namespace tincan
#endif //TINCAN_TINCAN_H_

