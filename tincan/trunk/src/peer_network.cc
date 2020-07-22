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
#include "peer_network.h"
#include "tincan_exception.h"
namespace tincan
{
PeerNetwork::PeerNetwork() :
  scavenge_interval(120000)
{}

PeerNetwork::~PeerNetwork()
{
  Clear();
}
/*
Adds a new adjacent node to the peer network. This is used when a new vlink is
created.
*/
void PeerNetwork::Add(shared_ptr<VirtualLink> vlink)
{
  vlink->is_valid_ = true;
  MacAddressType mac;
  size_t cnt = StringToByteArray(
    vlink->PeerInfo().mac_address, mac.begin(), mac.end());
  if(cnt != 6)
  {
    string emsg = "Converting the MAC to binary failed, the input string is: ";
    emsg.append(vlink->PeerInfo().mac_address);
    throw TCEXCEPT(emsg.c_str());
  }
  {
    lock_guard<mutex> lg(mac_map_mtx_);
    if(mac_map_.count(mac) == 1)
    {
      LOG(LS_INFO) << "Entry " << vlink->PeerInfo().mac_address <<
        " already exists in peer net. It will be updated.";
    }
    mac_map_[mac] = vlink;
    link_map_[vlink->Id()] = vlink;
  }
}

void PeerNetwork::Clear()
{
  lock_guard<mutex> lgm(mac_map_mtx_);
  mac_routes_.clear();
  mac_map_.clear();
  link_map_.clear();
}

shared_ptr<VirtualLink>
PeerNetwork::GetRoute(
  const MacAddressType& mac)
{
  lock_guard<mutex> lgm(mac_map_mtx_);
  HubEx & hux = mac_routes_.at(mac);
  hux.accessed = steady_clock::now();
  return hux.vl;
}

shared_ptr<VirtualLink>
PeerNetwork::GetVlink(
  const string & mac)
{
  MacAddressType mac_arr;
  StringToByteArray(mac, mac_arr.begin(), mac_arr.end());
  return GetVlink(mac_arr);
}

shared_ptr<VirtualLink>
PeerNetwork::GetVlink(
  const MacAddressType& mac)
{
  lock_guard<mutex> lgm(mac_map_mtx_);
  return mac_map_.at(mac);
}

shared_ptr<VirtualLink>
PeerNetwork::GetVlinkById(
  const string & link_id)
{
  lock_guard<mutex> lgm(mac_map_mtx_);
  return link_map_.at(link_id);
}

bool
PeerNetwork::Exists(
  const string & link_id)
{
  lock_guard<mutex> lgm(mac_map_mtx_);
  return (link_map_.count(link_id) == 1);
}

bool
PeerNetwork::IsAdjacent(
  const string & mac)
{
  MacAddressType mac_arr;
  StringToByteArray(mac, mac_arr.begin(), mac_arr.end());
  return IsAdjacent(mac_arr);
}

bool
PeerNetwork::IsAdjacent(
  const MacAddressType& mac)
{
  lock_guard<mutex> lgm(mac_map_mtx_);
  return (mac_map_.count(mac) == 1);
}

bool
PeerNetwork::IsRouteExists(
  const MacAddressType& mac)
{
  bool rv = false;
  lock_guard<mutex> lgm(mac_map_mtx_);
  if(mac_routes_.count(mac) == 1)
  {
    if(mac_routes_.at(mac).vl->is_valid_)
      rv = true;
    else
      mac_routes_.erase(mac);
  }
  return rv;
}

vector<string>
PeerNetwork::QueryVlinks()
{
  vector<string> vlids;
  lock_guard<mutex> lg(mac_map_mtx_);
  for(auto vl : mac_map_)
  {
    vlids.push_back(vl.second->Id());
  }
  return vlids;
}

/*
Used when a vlink is removed and the peer is no longer adjacent. All routes that
use this path must be removed as well.
*/
void
PeerNetwork::Remove(
  const string & link_id)
{
  try
  {
    lock_guard<mutex> lg(mac_map_mtx_);
    shared_ptr<VirtualLink> vl = link_map_.at(link_id);
    vl->is_valid_ = false;
    //remove the MAC for the adjacent node when tnl goes out of scope ref count
    //is decr, if it is 0 it's deleted 
    MacAddressType mac;
    StringToByteArray(vl->PeerInfo().mac_address, mac.begin(), mac.end());
    mac_map_.erase(mac);
    link_map_.erase(vl->Id());
  } catch(exception & e)
  {
    LOG(LS_WARNING) << e.what();
  } catch(...)
  {
    ostringstream oss;
    oss << "Failed to remove link: " << link_id;
    LOG(LS_WARNING) << oss.str().c_str();
  }
}

void
PeerNetwork::Run(Thread* thread)
{
  steady_clock::time_point accessed;
  milliseconds expiry_period = 3 * scavenge_interval;
  while(thread->ProcessMessages((int)scavenge_interval.count()))
  {
    accessed = steady_clock::now();
    list<MacAddressType> ml;
    lock_guard<mutex> lgm(mac_map_mtx_);
    for(auto & i : mac_routes_)
    {
      if(!i.second.vl->is_valid_)
        ml.push_back(i.first);
      else
      {
        std::chrono::duration<double, milli> elapsed = steady_clock::now()
          - i.second.accessed;
        if(elapsed > expiry_period)
          ml.push_back(i.first);
      }
    }
    for(auto & mac : ml)
    {
      LOG(LS_INFO) << "Scavenging route to "
        << ByteArrayToString(mac.begin(), mac.end());
      mac_routes_.erase(mac);
    }
    if(LOG_CHECK_LEVEL(LS_INFO))
    {
      LOG(LS_INFO) << "PeerNetwork scavenge took "
        << (steady_clock::now() - accessed).count() << " nanosecs.";
    }
  }
}

void PeerNetwork::UpdateRouteTable(
  MacAddressType & dest,
  MacAddressType & route)
{
  lock_guard<mutex> lg(mac_map_mtx_);
  //for(uint32_t i = 0; i < rts_desc["Table"].size(); i++)
  //{
  //  Json::Value & entry = rts_desc[i];
  //  entry["Identifier"]
  //    entry["Action"]
  //    entry["Destination"]
  //    entry["Path"]
  //}

  if(dest == route || mac_map_.count(route) == 0 ||
    (mac_map_.count(route) && !mac_map_.at(route)->is_valid_))
  {
    stringstream oss;
    oss << "Attempt to add INVALID route! DEST=" <<
      ByteArrayToString(dest.begin(), dest.end()) << " ROUTE=" <<
      ByteArrayToString(route.begin(), route.end());
    throw TCEXCEPT(oss.str().c_str());
  }
  mac_routes_[dest].vl = mac_map_.at(route);
  mac_routes_[dest].accessed = steady_clock::now();
  LOG(LS_INFO) << "Updated route to node=" <<
    ByteArrayToString(dest.begin(), dest.end()) << " through node=" <<
    ByteArrayToString(route.begin(), route.end()) << " vlink obj=" <<
    mac_routes_[dest].vl.get();
}
} // namespace tincan
