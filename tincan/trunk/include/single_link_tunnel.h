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
#ifndef SINGLE_LINK_TUNNEL_H_
#define SINGLE_LINK_TUNNEL_H_
#include "tincan_base.h"
#include "basic_tunnel.h"

namespace tincan
{
class SingleLinkTunnel :
  public BasicTunnel
{
public:
  SingleLinkTunnel(
    unique_ptr<TunnelDescriptor> descriptor,
    ControllerLink * ctrl_handle);
  virtual ~SingleLinkTunnel() = default;

  shared_ptr<VirtualLink> CreateVlink(
    unique_ptr<VlinkDescriptor> vlink_desc,
    unique_ptr<PeerDescriptor> peer_desc) override;

  void QueryInfo(
    Json::Value & tnl_info) override;

  void QueryLinkCas(
    const string & vlink_id,
    Json::Value & cas_info) override;

  void QueryLinkIds(
    vector<string> & link_ids) override;

  void QueryLinkInfo(
    const string & vlink_id,
    Json::Value & vlink_info) override;

  void SendIcc(
    const string & recipient_mac,
    const string & data) override;

  //void Start();

  void Shutdown() override;

  void StartIo() override;

  void StopIo() override;

  void RemoveLink(
    const string & vlink_id) override;

  void UpdateRouteTable(
    const Json::Value & rt_descr) override;

  //
  //FrameHandler implementation
  void VlinkReadComplete(
    uint8_t * data,
    uint32_t data_len,
    VirtualLink & vlink) override;
  //
  //AsyncIOComplete
  void TapReadComplete(
    AsyncIo * aio_rd) override;
  void TapWriteComplete(
    AsyncIo * aio_wr) override;

private:
  shared_ptr<VirtualLink> vlink_;
};
} //namespace tincan
#endif  // SINGLE_LINK_TUNNEL_H_
