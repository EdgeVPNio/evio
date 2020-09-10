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
#include "single_link_tunnel.h"
#include "tincan_exception.h"
#include "tincan_control.h"

namespace tincan
{
SingleLinkTunnel::SingleLinkTunnel(
  unique_ptr<TunnelDescriptor> descriptor,
  ControllerLink * ctrl_handle) :
  BasicTunnel(move(descriptor), ctrl_handle)
{}

shared_ptr<VirtualLink>
SingleLinkTunnel::CreateVlink(
  unique_ptr<VlinkDescriptor> vlink_desc,
  unique_ptr<PeerDescriptor> peer_desc)
{
  if(vlink_)
  {
    vlink_->PeerCandidates(peer_desc->cas);
    vlink_->StartConnections();
    RTC_LOG(LS_INFO) << "Added remote CAS to vlink w/ peer "
      << vlink_->PeerInfo().uid;
  }
  else
  {
    cricket::IceRole ir = cricket::ICEROLE_CONTROLLED;
    if(descriptor_->node_id < peer_desc->uid)
      ir = cricket::ICEROLE_CONTROLLING;
    string roles[] = { "CONTROLLING", "CONTROLLED" };
    RTC_LOG(LS_INFO) << "Creating " << roles[ir] << " vlink w/ peer " << peer_desc->uid;
    vlink_ = BasicTunnel::CreateVlink(move(vlink_desc), move(peer_desc), ir);
  }
  return vlink_;
}

void SingleLinkTunnel::QueryInfo(
  Json::Value & tnl_info)
{
  tnl_info[TincanControl::TunnelId] = descriptor_->uid;
  tnl_info[TincanControl::FPR] = Fingerprint();
  tnl_info[TincanControl::TapName] = tap_desc_->name;
  tnl_info[TincanControl::MAC] = MacAddress();
  tnl_info["LinkIds"] = Json::Value(Json::arrayValue);
  if(vlink_)
  {
    tnl_info["LinkIds"].append(vlink_->Id());
  }
}

void SingleLinkTunnel::QueryLinkCas(
  const string & vlink_id,
  Json::Value & cas_info)
{
  if(vlink_)
  {
    if(vlink_->IceRole() == cricket::ICEROLE_CONTROLLING)
      cas_info[TincanControl::IceRole] = TincanControl::Controlling.c_str();
    else if(vlink_->IceRole() == cricket::ICEROLE_CONTROLLED)
      cas_info[TincanControl::IceRole] = TincanControl::Controlled.c_str();

    cas_info[TincanControl::CAS] = vlink_->Candidates();
  }
}

void SingleLinkTunnel::QueryLinkIds(vector<string>& link_ids)
{
  if(vlink_)
    link_ids.push_back(vlink_->Id());
}

void SingleLinkTunnel::QueryLinkInfo(
  const string & vlink_id,
  Json::Value & vlink_info)
{
  if(vlink_)
  {
    if(vlink_->IceRole() == cricket::ICEROLE_CONTROLLING)
      vlink_info[TincanControl::IceRole] = TincanControl::Controlling;
    else
      vlink_info[TincanControl::IceRole] = TincanControl::Controlled;
    if(vlink_->IsReady())
    {
      LinkInfoMsgData md;
      md.vl = vlink_;
      net_worker_->Post(RTC_FROM_HERE, this, MSGID_QUERY_NODE_INFO, &md);
      md.msg_event.Wait(Event::kForever);
      vlink_info[TincanControl::Stats].swap(md.info);
      vlink_info[TincanControl::Status] = "ONLINE";
    }
    else
    {
      vlink_info[TincanControl::Status] = "OFFLINE";
      vlink_info[TincanControl::Stats] = Json::Value(Json::objectValue);
    }
  }
  else
  {
    vlink_info[TincanControl::Status] = "UNKNOWN";
    vlink_info[TincanControl::Stats] = Json::Value(Json::objectValue);
  }

}

void SingleLinkTunnel::SendIcc(
  const string & vlink_id,
  const string & data)
{
  if(!vlink_ || vlink_->Id() != vlink_id)
    throw TCEXCEPT("No vlink exists by the specified id");
  unique_ptr<IccMessage> icc = make_unique<IccMessage>();
  icc->Message((uint8_t*)data.c_str(), (uint16_t)data.length());
  unique_ptr<TransmitMsgData> md = make_unique<TransmitMsgData>();
  md->frm = move(icc);
  md->vl = vlink_;
  net_worker_->Post(RTC_FROM_HERE, this, MSGID_SEND_ICC, md.release());

}

void SingleLinkTunnel::Shutdown()
{
  if(vlink_ && vlink_->IsReady())
  {
    LinkInfoMsgData md;
    md.vl = vlink_;
    net_worker_->Post(RTC_FROM_HERE, this, MSGID_DISC_LINK, &md);
    md.msg_event.Wait(Event::kForever);
  }
  vlink_.reset();
  BasicTunnel::Shutdown();
}

void
SingleLinkTunnel::StartIo()
{
  tdev_->Up();
  BasicTunnel::StartIo();
}

void
SingleLinkTunnel::StopIo()
{
  tdev_->Down();
}

void SingleLinkTunnel::RemoveLink(
  const string & vlink_id)
{
  if(!vlink_)
    return;
  if(vlink_->Id() != vlink_id)
    throw TCEXCEPT("The specified VLink ID does not match this Tunnel");
  if(vlink_->IsReady())
  {
    LinkInfoMsgData md;
    md.vl = vlink_;
    net_worker_->Post(RTC_FROM_HERE, this, MSGID_DISC_LINK, &md);
    md.msg_event.Wait(Event::kForever);
  }
  vlink_.reset();
}

void
SingleLinkTunnel::UpdateRouteTable(
  const Json::Value & rt_descr)
{}

/*
The only operations for single link tunnels are sending ICCs and normal IO
*/
void SingleLinkTunnel::VlinkReadComplete(
  uint8_t * data,
  uint32_t data_len,
  VirtualLink & vlink)
{
  unique_ptr<TapFrame> frame = make_unique<TapFrame>(data, data_len);
  TapFrameProperties fp(*frame);
  if(fp.IsDtfMsg())
  {
    //frame->Dump("Frame from vlink");
    frame->BufferToTransfer(frame->Payload()); //write frame payload to TAP
    frame->BytesToTransfer(frame->PayloadLength());
    frame->SetWriteOp();
    tdev_->Write(*frame.release());
  }
  else if(fp.IsIccMsg())
  { // this is an ICC message, deliver to the controller
    unique_ptr<TincanControl> ctrl = make_unique<TincanControl>();
    ctrl->SetControlType(TincanControl::CTTincanRequest);
    Json::Value & req = ctrl->GetRequest();
    req[TincanControl::Command] = TincanControl::ICC;
    req[TincanControl::TunnelId] = descriptor_->uid;
    req[TincanControl::LinkId] = vlink.Id();
    req[TincanControl::Data] = string((char*)frame->Payload(),
      frame->PayloadLength());
    //RTC_LOG(LS_INFO) << " Delivering ICC to ctrl, data=\n"
    //<< req[TincanControl::Data].asString();
    ctrl_link_->Deliver(move(ctrl));
  }
  else
  {
    RTC_LOG(LS_ERROR) << "Unknown frame type received!";
    frame->Dump("Invalid header");
  }
}

void SingleLinkTunnel::TapReadComplete(
  AsyncIo * aio_rd)
{
  TapFrame * frame = static_cast<TapFrame*>(aio_rd->context_);
  if (!aio_rd->good_ || (aio_rd->BytesTransferred() < 0))
  {
    // TAP is most likely shutting down
    delete frame;
    RTC_LOG(LS_INFO) << "TAP read failure, cancelling IO";
  }
  else if(!vlink_)
  {
    // vlink is not yet created or has been destroyed, keep posting reads
    frame->Initialize();
    frame->BufferToTransfer(frame->Payload());
    frame->BytesToTransfer(frame->PayloadCapacity());
    if(0 != tdev_->Read(*frame))
    {
      // TAP read msg queue has shut down
      delete frame;
      RTC_LOG(LS_INFO) << "TAP read post failed, no more attempts will be made";
    }
  }
  else
  {
    frame->PayloadLength(frame->BytesTransferred());
    frame->BufferToTransfer(frame->Begin()); //write frame header + PL to vlink
    frame->BytesToTransfer(frame->Length());
    frame->Header(tp.kDtfMagic);
    TransmitMsgData *md = new TransmitMsgData;
    md->frm.reset(frame);
    md->vl = vlink_;
    net_worker_->Post(RTC_FROM_HERE, this, MSGID_TRANSMIT, md);
  }
}

void SingleLinkTunnel::TapWriteComplete(
  AsyncIo * aio_wr)
{
  //TapFrame * frame = static_cast<TapFrame*>(aio_wr->context_);
  delete static_cast<TapFrame*>(aio_wr->context_);
}

} // end namespace tincan
