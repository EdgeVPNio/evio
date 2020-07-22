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
#ifndef TINCAN_VIRTUAL_LINK_H_
#define TINCAN_VIRTUAL_LINK_H_
#include "tincan_base.h"
#include "webrtc/base/asyncpacketsocket.h"
#include "webrtc/base/json.h"
#include "webrtc/base/network.h"
#include "webrtc/base/sslfingerprint.h"
#include "webrtc/base/thread.h"
#include "webrtc/p2p/base/basicpacketsocketfactory.h"
#include "webrtc/p2p/base/dtlstransportchannel.h"
#include "webrtc/p2p/base/transportcontroller.h"
#include "webrtc/p2p/base/packettransportinterface.h"
#include "webrtc/p2p/base/p2ptransportchannel.h"
#include "webrtc/p2p/client/basicportallocator.h"
#include "tap_frame.h"
#include "peer_descriptor.h"
#include "turn_descriptor.h"

namespace tincan
{
using namespace rtc;
using cricket::TransportController;
using cricket::TransportChannelImpl;
using cricket::TransportChannel;
using cricket::ConnectionRole;
using rtc::PacketTransportInterface;

class PeerNetwork;

struct  VlinkDescriptor
{
  bool dtls_enabled;
  string uid;
  vector<string> stun_servers;
  vector<TurnDescriptor> turn_descs;
};

class VirtualLink :
  public sigslot::has_slots<>
{
public:
  friend PeerNetwork;
  VirtualLink(
    unique_ptr<VlinkDescriptor> vlink_desc,
    unique_ptr<PeerDescriptor> peer_desc,
    rtc::Thread* signaling_thread,
    rtc::Thread* network_thread);
  ~VirtualLink();

  string Name();

  void Initialize(
    BasicNetworkManager & network_manager,
    unique_ptr<SSLIdentity>sslid,
    SSLFingerprint const & local_fingerprint,
    cricket::IceRole ice_role);

  PeerDescriptor& PeerInfo()
  {
    return *peer_desc_.get();
  }

  void StartConnections();

  void Disconnect();

  bool IsReady();

  void Transmit(TapFrame & frame);

  string Candidates();

  string PeerCandidates();

  void PeerCandidates(const string & peer_cas);

  string Id()
  {
    return vlink_desc_->uid;
  }
  void GetStats(Json::Value & infos);

  cricket::IceRole IceRole()
  {
    return ice_role_;
  }

  bool IsGatheringComplete()
  {
    return gather_state_ == cricket::kIceGatheringComplete;
  }

  sigslot::signal1<string, single_threaded> SignalLinkUp;
  sigslot::signal1<string, single_threaded> SignalLinkDown;
  sigslot::signal2<string, string> SignalLocalCasReady;
  sigslot::signal3<uint8_t *, uint32_t, VirtualLink&> SignalMessageReceived;
private:
  void SetupTURN(vector<TurnDescriptor>);

  void OnCandidatesGathered(
    const string & transport_name,
    const cricket::Candidates & candidates);

  void OnGatheringState(
    cricket::IceGatheringState gather_state);

  void OnWriteableState(
    PacketTransportInterface * transport);

  void RegisterLinkEventHandlers();

  void AddRemoteCandidates(
    const string & candidates);

  void SetupICE(
    SSLFingerprint const & local_fingerprint);

  void OnReadPacket(
    PacketTransportInterface* transport,
    const char* data,
    size_t len,
    const PacketTime & ptime,
    int flags);

  void OnSentPacket(
    PacketTransportInterface * transport,
    const SentPacket & packet);

  unique_ptr<VlinkDescriptor> vlink_desc_;
  unique_ptr<PeerDescriptor> peer_desc_;
  std::mutex cas_mutex_;
  cricket::Candidates local_candidates_;
  const uint64_t tiebreaker_;
  cricket::IceRole ice_role_;
  ConnectionRole conn_role_;
  TransportChannel * channel_;
  unique_ptr<cricket::TransportDescription> local_description_;
  unique_ptr<cricket::TransportDescription> remote_description_;
  unique_ptr<SSLFingerprint> remote_fingerprint_;
  string content_name_;
  PacketOptions packet_options_;
  BasicPacketSocketFactory packet_factory_;
  unique_ptr<cricket::BasicPortAllocator> port_allocator_;
  unique_ptr<cricket::TransportController> transport_ctlr_;

  cricket::IceGatheringState gather_state_;
  bool is_valid_;
  rtc::Thread* signaling_thread_;
  rtc::Thread* network_thread_;
};
} //namespace tincan
#endif // !TINCAN_VIRTUAL_LINK_H_
