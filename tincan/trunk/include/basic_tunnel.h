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
#ifndef BASIC_TUNNEL_H_
#define BASIC_TUNNEL_H_
#include "tincan_base.h"
#ifdef min
#undef min
#endif //
#ifdef max
#undef max
#endif //
#include "rtc_base/ssl_identity.h"
#include "rtc_base/thread.h"
#include "rtc_base/third_party/sigslot/sigslot.h"
#include "rtc_base/strings/json.h"
#include "async_io.h"
#include "controller_handle.h"
#include "tapdev.h"
#include "tap_frame.h"
#include "tincan_exception.h"
#include "tunnel_descriptor.h"
#include "virtual_link.h"

namespace tincan
{
class BasicTunnel :
  public sigslot::has_slots<>,
  public MessageHandler
{
public:
  enum MSG_ID
  {
    MSGID_TRANSMIT,
    MSGID_SEND_ICC,
    MSGID_QUERY_NODE_INFO,
    MSGID_FWD_FRAME,
    MSGID_FWD_FRAME_RD,
    MSGID_DISC_LINK,
  };
  class TransmitMsgData : public MessageData
  {
  public:
    shared_ptr<VirtualLink> vl;
    unique_ptr<TapFrame> frm;
  };
  class LinkInfoMsgData : public MessageData
  {
  public:
    shared_ptr<VirtualLink> vl;
    Json::Value info;
    rtc::Event msg_event;
    LinkInfoMsgData() : info(Json::arrayValue), msg_event(false, false) {}
    ~LinkInfoMsgData() = default;
  };
  class LinkMsgData : public MessageData
  {
  public:
    shared_ptr<VirtualLink> vl;
    rtc::Event msg_event;
    LinkMsgData() : msg_event(false, false)
    {}
    ~LinkMsgData() = default;
  };

  BasicTunnel(
    unique_ptr<TunnelDescriptor> descriptor,
    ControllerLink * ctrl_handle);

  virtual ~BasicTunnel();

  virtual void Configure(
    unique_ptr<TapDescriptor> tap_desc,
    const vector<string>& ignored_list);

  virtual shared_ptr<VirtualLink> CreateVlink(
    unique_ptr<VlinkDescriptor> vlink_desc,
    unique_ptr<PeerDescriptor> peer_desc) = 0;

  virtual TunnelDescriptor & Descriptor();
 
  virtual string Fingerprint();

  virtual void InjectFame(
    string && data);

  virtual string Name();

  virtual string MacAddress();

  virtual void QueryInfo(
    Json::Value & tnl_info) = 0;

  virtual void QueryLinkIds(
    vector<string> & link_ids) = 0;

  virtual void QueryLinkInfo(
    const string & vlink_id,
    Json::Value & vlink_info) = 0;

  virtual void QueryLinkCas(
    const string & vlink_id,
    Json::Value & cas_info) = 0;

  virtual void SendIcc(
    const string & vlink_id,
    const string & data) = 0;

  virtual void Shutdown();

  virtual void Start();

  virtual void StartIo();

  virtual void StopIo() {}

  virtual void RemoveLink(
    const string & vlink_id) = 0;

  virtual void UpdateRouteTable(
    const Json::Value & rt_descr) = 0;

  //
  //FrameHandler implementation
  virtual void VlinkReadComplete(
    uint8_t * data,
    uint32_t data_len,
    VirtualLink & vlink) = 0;
  //
  //AsyncIOComplete
  virtual void TapReadComplete(
    AsyncIo * aio_rd) = 0;
  virtual void TapWriteComplete(
    AsyncIo * aio_wr) = 0;
  //
  //MessageHandler overrides
  void OnMessage(
    Message* msg) override;
protected:
  void SetIgnoredNetworkInterfaces(
    const vector<string>& ignored_list);

  unique_ptr<VirtualLink> CreateVlink(
    unique_ptr<VlinkDescriptor> vlink_desc,
    unique_ptr<PeerDescriptor>
    peer_desc, cricket::IceRole ice_role);
  virtual void VLinkUp(
    string vlink_id);
  virtual void VLinkDown(
    string vlink_id);
  unique_ptr<TapDev> tdev_;
  unique_ptr<TapDescriptor> tap_desc_;
  unique_ptr<TunnelDescriptor> descriptor_;
  //shared_ptr<ControllerLink> ctrl_link_;
  ControllerLink * ctrl_link_;
  unique_ptr<rtc::SSLIdentity> sslid_;
  unique_ptr<rtc::SSLFingerprint> local_fingerprint_;
  rtc::Thread* net_worker_;
  rtc::Thread* sig_worker_;
  rtc::BasicNetworkManager net_manager_;
};
}  // namespace tincan
#endif  // BASIC_TUNNEL_H_
