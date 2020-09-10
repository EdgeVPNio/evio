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
#include "virtual_link.h"
#include "rtc_base/string_encode.h"
#include "tincan_exception.h"
#include "turn_descriptor.h"
namespace tincan
{
using namespace rtc;
VirtualLink::VirtualLink(
  unique_ptr<VlinkDescriptor> vlink_desc,
  unique_ptr<PeerDescriptor> peer_desc,
  rtc::Thread* signaling_thread,
  rtc::Thread* network_thread) :
  vlink_desc_(move(vlink_desc)),
  peer_desc_(move(peer_desc)),
  tiebreaker_(rtc::CreateRandomId64()),
  conn_role_(cricket::CONNECTIONROLE_ACTPASS),
  packet_options_(DSCP_DEFAULT),
  packet_factory_(network_thread),
  gather_state_(cricket::kIceGatheringNew),
  is_valid_(false),
  signaling_thread_(signaling_thread),
  network_thread_(network_thread)
{
  content_name_.append(vlink_desc_->uid.substr(0, 7));
}

VirtualLink::~VirtualLink()
{}

string VirtualLink::Name()
{
  return content_name_;
}

void
VirtualLink::Initialize(
  BasicNetworkManager & network_manager,
  unique_ptr<SSLIdentity>sslid,
  SSLFingerprint const & local_fingerprint,
  cricket::IceRole ice_role)
{
  ice_role_ = ice_role;

  cricket::ServerAddresses stun_addrs;
  for (auto stun_server : vlink_desc_->stun_servers)
  {
    rtc::SocketAddress stun_addr;
    stun_addr.FromString(stun_server);
    stun_addrs.insert(stun_addr);
  }
  port_allocator_.reset(new cricket::BasicPortAllocator(
  &network_manager, &packet_factory_, stun_addrs));

  port_allocator_->set_flags(cricket::PORTALLOCATOR_DISABLE_TCP);
  SetupTURN(vlink_desc_->turn_descs);
  transport_ctlr_ = make_unique<JsepTransportController>(
                        signaling_thread_,
                        network_thread_,
                        port_allocator_.get(),
                        /*async_resolver_factory*/ nullptr,
                        config);

  transport_ctlr_->SetLocalCertificate(RTCCertificate::Create(move(sslid)));
  //replacing CreateTransportChannel
  channel_ = make_unique<P2PTransportChannel>(
                content_name_,
                cricket::ICE_CANDIDATE_COMPONENT_DEFAULT,
                port_allocator_.get());
  RegisterLinkEventHandlers();
  SetupICE(local_fingerprint);
  transport_ctlr_->MaybeStartGathering();

  return;
}

/* Parses the string delimited list of candidates and adds
them to the P2P transport thereby creating ICE connections
*/
void
VirtualLink::AddRemoteCandidates(
  const string & candidates)
{
  std::istringstream iss(candidates);
  cricket::Candidates cas_vec;
  do {
    string candidate_str;
    iss >> candidate_str;
    vector<string> fields;
    size_t len = rtc::split(candidate_str, tp.kCandidateDelim, &fields);
    rtc::SocketAddress sa;
    if(len >= 10) {
      sa.FromString(fields[2].append(":").append(fields[3]));
      cricket::Candidate candidate(
      atoi(fields[0].c_str()),  //component
      fields[1],                //protocol
      sa,                       //socket address
      atoi(fields[4].c_str()),  //priority
      fields[5],                //username
      fields[6],                //password
      fields[7],                //type
      atoi(fields[8].c_str()), //generation
      fields[9]);              //foundation
      cas_vec.push_back(candidate);
    }
  } while(iss);
  if (!(transport_ctlr_->AddRemoteCandidates(content_name_, cas_vec).ok()))
     throw TCEXCEPT(string("Failed to add remote candidates - "));
  return;
}

void
VirtualLink::OnReadPacket(
  PacketTransportInternal *,
  const char * data,
  size_t len,
  const int64_t &,
  int)
{
  SignalMessageReceived((uint8_t*)data, *(uint32_t*)&len, *this);
}

void
VirtualLink::OnSentPacket(
  PacketTransportInternal *,
  const rtc::SentPacket &)
{
  //nothing to do atm ...
}

void VirtualLink::OnCandidatesGathered(
  const string &,
  const cricket::Candidates & candidates)
{
  std::unique_lock<std::mutex> lk(cas_mutex_);
  local_candidates_.insert(local_candidates_.end(), candidates.begin(),
    candidates.end());
  return;
}

void VirtualLink::OnGatheringState(
  cricket::IceGatheringState gather_state)
{
  gather_state_ = gather_state;
  if(gather_state == cricket::kIceGatheringComplete)
    SignalLocalCasReady(vlink_desc_->uid, Candidates());
  return;
}

void VirtualLink::OnWriteableState(
  PacketTransportInternal * transport)
{
  if(transport->writable())
  {
    RTC_LOG(LS_INFO) << "Connection established to: " << peer_desc_->uid;
    SignalLinkUp(vlink_desc_->uid);
  }
  else
  {
    RTC_LOG(LS_INFO) << "Link NOT writeable: " << peer_desc_->uid;
    SignalLinkDown(vlink_desc_->uid);
  }
}

void
VirtualLink::RegisterLinkEventHandlers()
{
  channel_->SignalReadPacket.connect(this, &VirtualLink::OnReadPacket);
  channel_->SignalSentPacket.connect(this, &VirtualLink::OnSentPacket);
  channel_->SignalWritableState.connect(this, &VirtualLink::OnWriteableState);
  //channel_->SignalReadyToSend.connect(this, &VirtualLink::OnWriteableState);

  transport_ctlr_->SignalIceCandidatesGathered.connect(
    this, &VirtualLink::OnCandidatesGathered);
  transport_ctlr_->SignalIceGatheringState.connect(
    this, &VirtualLink::OnGatheringState);
}

void VirtualLink::Transmit(TapFrame & frame)
{
  int status = channel_->SendPacket((const char*)frame.BufferToTransfer(),
    frame.BytesToTransfer(), packet_options_, 0);
  if(status < 0)
    RTC_LOG(LS_INFO) << "Vlink send failed";
}

string VirtualLink::Candidates()
{
  std::ostringstream oss;
  for (auto & cnd : local_candidates_)
  {
    oss << cnd.component()
      << tp.kCandidateDelim << cnd.protocol()
      << tp.kCandidateDelim << cnd.address().ToString()
      << tp.kCandidateDelim << cnd.priority()
      << tp.kCandidateDelim << cnd.username()
      << tp.kCandidateDelim << cnd.password()
      << tp.kCandidateDelim << cnd.type()
      << tp.kCandidateDelim << cnd.generation()
      << tp.kCandidateDelim << cnd.foundation()
      << " ";
  }
  return oss.str();
}

string VirtualLink::PeerCandidates()
{
  return peer_desc_->cas;
}

void
VirtualLink::PeerCandidates(
  const string & peer_cas)
{
  peer_desc_->cas = peer_cas;
}

void
VirtualLink::GetStats(Json::Value & stats)
{
  cricket::IceTransportStats infos;
  channel_->GetStats(&infos);
  for(const cricket::ConnectionInfo& info : infos.connection_infos)//(auto info: infos)
  {
      Json::Value stat(Json::objectValue);
      stat["best_conn"] = info.best_connection;
      stat["writable"] = info.writable;
      stat["receiving"] = info.receiving;
      stat["timeout"] = info.timeout;
      stat["new_conn"] = info.new_connection;

      stat["rtt"] = (Json::UInt64)info.rtt;
      stat["sent_total_bytes"] = (Json::UInt64)info.sent_total_bytes;
      stat["sent_bytes_second"] = (Json::UInt64)info.sent_bytes_second;
      stat["sent_discarded_packets"] = (Json::UInt64)info.sent_discarded_packets;
      stat["sent_total_packets"] = (Json::UInt64)info.sent_total_packets;
      stat["sent_ping_requests_total"] = (Json::UInt64)info.sent_ping_requests_total;
      stat["sent_ping_requests_before_first_response"] = (Json::UInt64)info.sent_ping_requests_before_first_response;
      stat["sent_ping_responses"] = (Json::UInt64)info.sent_ping_responses;

      stat["recv_total_bytes"] = (Json::UInt64)info.recv_total_bytes;
      stat["recv_bytes_second"] = (Json::UInt64)info.recv_bytes_second;
      stat["recv_ping_requests"] = (Json::UInt64)info.recv_ping_requests;
      stat["recv_ping_responses"] = (Json::UInt64)info.recv_ping_responses;

      stat["local_candidate"] = info.local_candidate.ToString();
      stat["remote_candidate"] = info.remote_candidate.ToString();
      stat["state"] = (Json::UInt)info.state;
      // http://tools.ietf.org/html/rfc5245#section-5.7.4
    stats.append(stat);
  }
}

void
VirtualLink::SetupICE(
  SSLFingerprint const & local_fingerprint)
{
  size_t pos = peer_desc_->fingerprint.find(' ');
  string alg, fp;
  if(pos != string::npos)
  {
    alg = peer_desc_->fingerprint.substr(0, pos);
    fp = peer_desc_->fingerprint.substr(++pos);
    remote_fingerprint_.reset(
      rtc::SSLFingerprint::CreateFromRfc4572(alg, fp));
  }
  //cricket::IceConfig ic;
  //ic.continual_gathering_policy = cricket::GATHER_CONTINUALLY_AND_RECOVER;
  //transport_ctlr_->SetIceConfig(ic);
  channel_->SetIceRole(ice_role_);
  cricket::ConnectionRole remote_conn_role = cricket::CONNECTIONROLE_ACTIVE;
  conn_role_ = cricket::CONNECTIONROLE_ACTPASS;
  if(cricket::ICEROLE_CONTROLLING == ice_role_) {
    conn_role_ = cricket::CONNECTIONROLE_ACTIVE;
    remote_conn_role = cricket::CONNECTIONROLE_ACTPASS;
  }

   cricket::TransportDescription local_transport_desc
   (vector<string>(),
    tp.kIceUfrag,
    tp.kIcePwd,
    cricket::ICEMODE_FULL,
    conn_role_,
    & local_fingerprint);

   cricket::TransportDescription remote_transport_desc
   (vector<string>(),
    tp.kIceUfrag,
    tp.kIcePwd,
    cricket::ICEMODE_FULL,
    remote_conn_role,
    remote_fingerprint_.get());


   local_description_->AddTransportInfo(cricket::TransportInfo(content_name_, local_transport_desc));
   remote_description_->AddTransportInfo(cricket::TransportInfo(content_name_, remote_transport_desc));

  if(cricket::ICEROLE_CONTROLLING == ice_role_)
  {
    //when controlling the remote description must be set first.
    transport_ctlr_->SetRemoteDescription(SdpType::kOffer, remote_description_.get());
    transport_ctlr_->SetLocalDescription(SdpType::kAnswer, local_description_.get());
  }
  else if(cricket::ICEROLE_CONTROLLED == ice_role_)
  {
    transport_ctlr_->SetLocalDescription(SdpType::kOffer, local_description_.get());
    transport_ctlr_->SetRemoteDescription(SdpType::kAnswer, remote_description_.get());
  }
  else
  {
    RTC_LOG(LS_WARNING) << "Invalid ICE role specified: " << (uint32_t)ice_role_;
    throw TCEXCEPT("Invalid ICE role specified");
  }

}

void
VirtualLink::SetupTURN(
  const vector<TurnDescriptor> turn_descs)
{
  if(turn_descs.empty()) {
    RTC_LOG(LS_INFO) << "No TURN Server address provided";
    return;
  }

  for (auto turn_desc : turn_descs)
  {
    if (turn_desc.username.empty() || turn_desc.password.empty())
    {
      RTC_LOG(LS_WARNING) << "TURN credentials were not provided for hostname " << turn_desc.server_hostname;
      continue;
    }

    vector<string> addr_port;
    rtc::split(turn_desc.server_hostname, ':', &addr_port);
    if(addr_port.size() != 2)
    {
      RTC_LOG(LS_INFO) << "Invalid TURN Server address provided. Address must contain a port number separated by a \":\".";
      continue;
    }
    cricket::RelayServerConfig relay_config_udp(addr_port[0], stoi(addr_port[1]),
        turn_desc.username, turn_desc.password, cricket::PROTO_UDP);
    port_allocator_->AddTurnServer(relay_config_udp);
  }
}

void
VirtualLink::StartConnections()
{
  if(peer_desc_->cas.length() == 0)
    throw TCEXCEPT("The vlink connection cannot be started as no connection"
      " candidates were specified in the vlink descriptor");
  AddRemoteCandidates(peer_desc_->cas);
}
void VirtualLink::Disconnect()
{
   channel_.reset();
}

bool VirtualLink::IsReady()
{
  return channel_->writable();
}
} // end namespace tincan
