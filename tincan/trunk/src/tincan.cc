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

#include "tincan.h"
#include "tincan_exception.h"
#include "turn_descriptor.h"
namespace tincan
{
Tincan::Tincan() :
  exit_event_(false, false)
{}

Tincan::~Tincan()
{
}

void
Tincan::SetIpopControllerLink(
  //shared_ptr<IpopControllerLink> ctrl_handle)
  IpopControllerLink * ctrl_handle)
{
  ctrl_link_ = ctrl_handle;
}

void Tincan::CreateTunnel(
  const Json::Value & tnl_desc,
  Json::Value & tnl_info)
{
  unique_ptr<TunnelDescriptor> td(new TunnelDescriptor);
  td->uid = tnl_desc[TincanControl::TunnelId].asString();
  td->node_id = tnl_desc[TincanControl::NodeId].asString();
  if(IsTunnelExisit(td->uid))
    throw TCEXCEPT("The specified Tunnel identifier already exists");

  Json::Value stun_servers = tnl_desc["StunServers"];
  for (Json::Value::ArrayIndex i = 0; i < stun_servers.size(); ++i)
  {
    td->stun_servers.push_back(stun_servers[i].asString());
  }

  Json::Value turn_servers = tnl_desc["TurnServers"];
  for (Json::Value::ArrayIndex i = 0; i < turn_servers.size(); ++i)
  {
    TurnDescriptor turn_desc(
      turn_servers[i]["Address"].asString(),
      turn_servers[i]["User"].asString(),
      turn_servers[i]["Password"].asString());
    td->turn_descs.push_back(turn_desc);
  }
  td->enable_ip_mapping = false;
  unique_ptr<BasicTunnel> tnl;
 /* if(tnl_desc[TincanControl::Type].asString() == "VNET")
  {
    tnl = make_unique<MultiLinkTunnel>(move(td), ctrl_link_);
  }
  else 
  if(tnl_desc[TincanControl::Type].asString() == "TUNNEL")
  {*/
  tnl = make_unique<SingleLinkTunnel>(move(td), ctrl_link_);
  //}
  //else
  //  throw TCEXCEPT("Invalid Tunnel type specified");
  unique_ptr<TapDescriptor> tap_desc = make_unique<TapDescriptor>();
  tap_desc->name = tnl_desc["TapName"].asString();
  tap_desc->ip4 = tnl_desc["IP4"].asString();
  tap_desc->prefix4 = tnl_desc["IP4PrefixLen"].asUInt();
  tap_desc->mtu4 = tnl_desc[TincanControl::MTU4].asUInt();

  Json::Value network_ignore_list =
  tnl_desc[TincanControl::IgnoredNetInterfaces];
  int count = network_ignore_list.size();
  vector<string> if_list(count);
  for (int i = 0; i < count; i++)
  {
    if_list[i] = network_ignore_list[i].asString();
  }
  tnl->Configure(move(tap_desc), if_list);
  tnl->Start();
  tnl->QueryInfo(tnl_info);
  lock_guard<mutex> lg(tunnels_mutex_);
  tunnels_.push_back(move(tnl));

  return;
}

void
Tincan::CreateVlink(
  const Json::Value & link_desc,
  const TincanControl & control)
{
  unique_ptr<VlinkDescriptor> vl_desc = make_unique<VlinkDescriptor>();
  vl_desc->uid = link_desc[TincanControl::LinkId].asString();
  unique_ptr<Json::Value> resp = make_unique<Json::Value>(Json::objectValue);
  Json::Value & tnl_info = (*resp)[TincanControl::Message];
  string tnl_id = link_desc[TincanControl::TunnelId].asString();
  if(!IsTunnelExisit(tnl_id))
  {
    CreateTunnel(link_desc, tnl_info);
  }
  else
  {
    TunnelFromId(tnl_id).QueryInfo(tnl_info);
  }
  unique_ptr<PeerDescriptor> peer_desc = make_unique<PeerDescriptor>();
  peer_desc->uid =
    link_desc[TincanControl::PeerInfo][TincanControl::UID].asString();
  peer_desc->vip4 =
    link_desc[TincanControl::PeerInfo][TincanControl::VIP4].asString();
  peer_desc->cas =
    link_desc[TincanControl::PeerInfo][TincanControl::CAS].asString();
  peer_desc->fingerprint =
    link_desc[TincanControl::PeerInfo][TincanControl::FPR].asString();
  peer_desc->mac_address =
    link_desc[TincanControl::PeerInfo][TincanControl::MAC].asString();

  vl_desc->dtls_enabled = true;

  BasicTunnel & tnl = TunnelFromId(tnl_id);
  shared_ptr<VirtualLink> vlink =
    tnl.CreateVlink(move(vl_desc), move(peer_desc));
  unique_ptr<TincanControl> ctrl = make_unique<TincanControl>(control);
  if(!vlink->IsGatheringComplete())
  {
    ctrl->SetResponse(move(resp));
    std::lock_guard<std::mutex> lg(inprogess_controls_mutex_);
    inprogess_controls_[link_desc[TincanControl::LinkId].asString()]
      = move(ctrl);

    vlink->SignalLocalCasReady.connect(this, &Tincan::OnLocalCasUpdated);
  }
  else
  {
    (*resp)["Message"]["CAS"] = vlink->Candidates();
    (*resp)["Success"] = true;
    ctrl->SetResponse(move(resp));
    ctrl_link_->Deliver(move(ctrl));
  }
}

void
Tincan::InjectFrame(
  const Json::Value & frame_desc)
{
  const string & tnl_id = frame_desc[TincanControl::TunnelId].asString();
  BasicTunnel & ol = TunnelFromId(tnl_id);
  ol.InjectFame(frame_desc[TincanControl::Data].asString());
}

void
Tincan::QueryLinkCas(
  const Json::Value & link_desc,
  Json::Value & cas_info)
{
  const string tnl_id = link_desc[TincanControl::TunnelId].asString();
  const string vlid = link_desc[TincanControl::LinkId].asString();
  BasicTunnel & ol = TunnelFromId(tnl_id);
  ol.QueryLinkCas(vlid, cas_info);
}

void
Tincan::QueryLinkStats(
  const Json::Value & tunnel_ids,
  Json::Value & stat_info)
{
  for(uint32_t i = 0; i < tunnel_ids["TunnelIds"].size(); i++)
  {
    vector<string>link_ids;
    string tnl_id = tunnel_ids["TunnelIds"][i].asString();
    BasicTunnel & ol = TunnelFromId(tnl_id);
    ol.QueryLinkIds(link_ids);
    for(auto vlid : link_ids)
    {
      ol.QueryLinkInfo(vlid, stat_info[tnl_id][vlid]);
    }
  }

}

void
Tincan::QueryTunnelInfo(
  const Json::Value & tnl_desc,
  Json::Value & tnl_info)
{
  BasicTunnel & ol = TunnelFromId(tnl_desc[TincanControl::TunnelId].asString());
  ol.QueryInfo(tnl_info);
}

void 
Tincan::RemoveTunnel(
  const Json::Value & tnl_desc)
{
  const string tnl_id = tnl_desc[TincanControl::TunnelId].asString();
  if(tnl_id.empty())
    throw TCEXCEPT("No Tunnel ID was specified");
  
  lock_guard<mutex> lg(tunnels_mutex_);
  for(auto tnl = tunnels_.begin(); tnl != tunnels_.end(); tnl++)
  {
    if((*tnl)->Descriptor().uid.compare(tnl_id) == 0)
    {
      (*tnl)->Shutdown();
      tunnels_.erase(tnl);
      RTC_LOG(LS_INFO) << "RemoveTunnel: Instance erased from collection " << tnl_id;
      return;
    }
  }
  RTC_LOG(LS_WARNING) << "RemoveTunnel: No such virtual network exists " << tnl_id;
}

void
Tincan::RemoveVlink(
  const Json::Value & link_desc)
{
  const string tnl_id = link_desc[TincanControl::TunnelId].asString();
  const string vlid = link_desc[TincanControl::LinkId].asString();
  if(tnl_id.empty() || vlid.empty())
    throw TCEXCEPT("Required identifier not specified");

  lock_guard<mutex> lg(tunnels_mutex_);
  for(auto & tnl : tunnels_)
  {
    if(tnl->Descriptor().uid.compare(tnl_id) == 0)
    {
      tnl->RemoveLink(vlid);
    }
  }
}

void
Tincan::SendIcc(
  const Json::Value & icc_desc)
{
  const string tnl_id = icc_desc[TincanControl::TunnelId].asString();
  const string & link_id = icc_desc[TincanControl::LinkId].asString();
  if(icc_desc[TincanControl::Data].isString())
  {
    const string & data = icc_desc[TincanControl::Data].asString();
    BasicTunnel & ol = TunnelFromId(tnl_id);
    ol.SendIcc(link_id, data);
  }
  else
    throw TCEXCEPT("Icc data is not represented as a string");
}

void
Tincan::OnLocalCasUpdated(
  string link_id,
  string lcas)
{
  if(lcas.empty())
  {
    lcas = "No local candidates available on this vlink";
    RTC_LOG(LS_WARNING) << lcas;
  }
  bool to_deliver = false;
  unique_ptr<TincanControl> ctrl;
  {
    std::lock_guard<std::mutex> lg(inprogess_controls_mutex_);
    auto itr = inprogess_controls_.begin();
    for(; itr != inprogess_controls_.end(); itr++)
    {
      if(itr->first == link_id)
      {
        to_deliver = true;
        ctrl = move(itr->second);
        Json::Value & resp = ctrl->GetResponse();
        resp["Message"]["CAS"] = lcas;
        resp["Success"] = true;
        inprogess_controls_.erase(itr);
        break;
      }
    }
  }
  if(to_deliver)
  {
    ctrl_link_->Deliver(move(ctrl));
  }
}

void Tincan::UpdateRouteTable(
  const Json::Value & rts_desc)
{
  string tnl_id = rts_desc[TincanControl::TunnelId].asString();
  BasicTunnel & ol = TunnelFromId(tnl_id);
  ol.UpdateRouteTable(rts_desc["Table"]);
}

void
Tincan::Run()
{
  //TODO:Code cleanup
#if defined(_IPOP_WIN)
  self_ = this;
  SetConsoleCtrlHandler(ControlHandler, TRUE);
#endif // _IPOP_WIN

  //Start tincan control to get config from Controller
  unique_ptr<ControlDispatch> ctrl_dispatch(new ControlDispatch);
  ctrl_dispatch->SetDispatchToTincanInf(this);
  ctrl_listener_ = make_shared<ControlListener>(move(ctrl_dispatch));
  ctrl_listener_->Run();
  //ctl_thread_->Start(ctrl_listener_.get());
  exit_event_.Wait(Event::kForever);
}

bool
Tincan::IsTunnelExisit(
  const string & tnl_id)
{
  lock_guard<mutex> lg(tunnels_mutex_);
  for(auto const & tnl : tunnels_) {
    if(tnl->Descriptor().uid.compare(tnl_id) == 0)
      return true;
  }
  return false;
}

BasicTunnel &
Tincan::TunnelFromId(
  const string & tnl_id)
{
  lock_guard<mutex> lg(tunnels_mutex_);
  for(auto const & tnl : tunnels_)
  {
    //list of tunnels will be small enough where a linear search is satifactory
    if(tnl->Descriptor().uid.compare(tnl_id) == 0)
      return *tnl.get();
  }
  string msg("No virtual network exists by this name: ");
  msg.append(tnl_id);
  throw TCEXCEPT(msg.c_str());
}
//-----------------------------------------------------------------------------
void Tincan::OnStop() {
  Shutdown();
  exit_event_.Set();
}

void
Tincan::Shutdown()
{
  lock_guard<mutex> lg(tunnels_mutex_);
  ctrl_listener_->Quit();
  for(auto const & tnl : tunnels_) {
    tnl->Shutdown();
  }
  tunnels_.clear();
}

/*
FUNCTION:ControlHandler
PURPOSE: Handles keyboard signals
PARAMETERS: The signal code
RETURN VALUE: Success/Failure
++*/
#if defined(_IPOP_WIN)
BOOL __stdcall Tincan::ControlHandler(DWORD CtrlType) {
  switch(CtrlType) {
  case CTRL_BREAK_EVENT:  // use Ctrl+C or Ctrl+Break to send
  case CTRL_C_EVENT:      // termination signal
    cout << "Stopping tincan... " << std::endl;
    self_->OnStop();
    return(TRUE);
  }
  return(FALSE);
}
#endif // _IPOP_WIN
} // namespace tincan
