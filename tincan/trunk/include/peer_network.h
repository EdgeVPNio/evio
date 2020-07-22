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
#if !defined(_TINCAN_PEER_NETWORK_H_)
#define _TINCAN_PEER_NETWORK_H_
#include "tincan_base.h"
#include "virtual_link.h"
#include <sparsepp/spp.h>

using spp::sparse_hash_map;

namespace tincan
{
class PeerNetwork :
  public Runnable
{
public:
  PeerNetwork();
  ~PeerNetwork();
  void Add(shared_ptr<VirtualLink> vlink);
  void Clear();
  shared_ptr<VirtualLink> GetRoute(const MacAddressType & mac);
  shared_ptr<VirtualLink> GetVlink(const string & mac);
  shared_ptr<VirtualLink> GetVlink(const MacAddressType & mac);
  shared_ptr<VirtualLink> GetVlinkById(const string & link_id);
  bool Exists(const string & link_id);
  bool IsAdjacent(const string & mac);
  bool IsAdjacent(const MacAddressType& mac);
  bool IsRouteExists(const MacAddressType& mac);
  vector<string> QueryVlinks();
  void Remove(const string & link_id);
  void UpdateRouteTable(MacAddressType & dest, MacAddressType & route);
private:
  struct MacAddressHasher
  {
    size_t operator()(const MacAddressType& mac) const
    {
      size_t h = 0;
      for(auto e : mac)
      {
        h ^= hash<uint8_t>{}(e)+0x9e3779b9 + (h << 6) + (h >> 2);
      }
      return h;
    }
  };
  struct Width6t8
  {
    size_t operator()(const MacAddressType& mac) const
    {
      size_t h = 0;
      memcpy(&h, mac.data(), 6);
      return h;
    }
  };
  struct HubEx
  {
    HubEx() : accessed(steady_clock::now())
    {}
    shared_ptr<VirtualLink> vl;
    steady_clock::time_point accessed;
  };
  mutex mac_map_mtx_;
  unordered_map<string, shared_ptr<VirtualLink>> link_map_;
  //unordered_map<MacAddressType, shared_ptr<VirtualLink>, MacAddressHasher> mac_map_;
  sparse_hash_map<MacAddressType, shared_ptr<VirtualLink>, MacAddressHasher>mac_map_;
  unordered_map<MacAddressType, HubEx, MacAddressHasher> mac_routes_;
  void Run(Thread* thread) override;
  milliseconds const scavenge_interval;
};

} // namespace tincan
#endif //_TINCAN_PEER_NETWORK_H_
