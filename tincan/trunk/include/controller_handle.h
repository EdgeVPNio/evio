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
#ifndef TINCAN_CONTROLLER_HANDLE_H_
#define TINCAN_CONTROLLER_HANDLE_H_
#include "tincan_base.h"
#include "tincan_control.h"

namespace tincan {
  class ControllerLink
  {
  public:
    virtual ~ControllerLink() = default;
    virtual void Deliver(
      TincanControl & ctrl_resp) = 0;

    virtual void Deliver(
      unique_ptr<TincanControl> ctrl_resp) = 0;
  };

  class DispatchToListenerInf
  {
  public:
    virtual ~DispatchToListenerInf() = default;
    virtual void CreateControllerLink(
      unique_ptr<SocketAddress> controller_addr) = 0;
    virtual ControllerLink & GetControllerLink() = 0;
  };

  class TincanDispatchInterface
  {
  public:
    virtual ~TincanDispatchInterface() = default;

    virtual void CreateTunnel(
      const Json::Value & tnl_desc,
      Json::Value & tnl_info) = 0;

    virtual void CreateVlink(
      const Json::Value & link_desc,
      const TincanControl & control) = 0;

    virtual void InjectFrame(
      const Json::Value & frame_desc) = 0;

    virtual void QueryLinkStats(
      const Json::Value & link_desc,
      Json::Value & node_info) = 0;

    virtual void QueryTunnelInfo(
      const Json::Value & tnl_desc,
      Json::Value & state_data) = 0;

    virtual void QueryLinkCas(
      const Json::Value & link_desc,
      Json::Value & cas_info) = 0;

    virtual void RemoveTunnel(
      const Json::Value & tnl_desc) = 0;

    virtual void RemoveVlink(
      const Json::Value & link_desc) = 0;

    virtual void SendIcc(
      const Json::Value & icc_desc) = 0;

    virtual void SetControllerLink(
      ControllerLink * ctrl_link) = 0;

    virtual void UpdateRouteTable(
      const Json::Value & rts_desc) = 0;
};
}  // namespace tincan
#endif  // TINCAN_CONTROLLER_HANDLE_H_
