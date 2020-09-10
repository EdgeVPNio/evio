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
#include "basic_tunnel.h"
#include "rtc_base/third_party/base64/base64.h"
#include "tincan_control.h"
namespace tincan
{
  extern TincanParameters tp;
  BasicTunnel::BasicTunnel(
  unique_ptr<TunnelDescriptor> descriptor,
  ControllerLink * ctrl_handle) :
  tdev_(nullptr),
  descriptor_(move(descriptor)),
  ctrl_link_(ctrl_handle)
{
  tdev_ = make_unique<TapDev>();
  net_worker_ = new Thread(SocketServer::CreateDefault());
  sig_worker_ = new Thread(SocketServer::CreateDefault());
}

BasicTunnel::~BasicTunnel()
{
  delete net_worker_;
  delete sig_worker_;
}

void
BasicTunnel::Configure(
  unique_ptr<TapDescriptor> tap_desc,
  const vector<string>& ignored_list)
{
  tap_desc_ = move(tap_desc);
  //initialize the Tap Device
  tdev_->Open(*tap_desc_.get());
  //create X509 identity for secure connections
  string sslid_name = descriptor_->node_id + descriptor_->uid;
  sslid_ = rtc::SSLIdentity::Create(sslid_name, rtc::KT_RSA);
  if(!sslid_)
    throw TCEXCEPT("Failed to generate SSL Identity");
  local_fingerprint_ = rtc::SSLFingerprint::CreateUnique("DIGEST_SHA_3", *sslid_.get());
  if(!local_fingerprint_)
    throw TCEXCEPT("Failed to create the local finger print");
  SetIgnoredNetworkInterfaces(ignored_list);
}

void
BasicTunnel::Start()
{
  net_worker_->Start();
  sig_worker_->Start();
  tdev_->read_completion_.connect(this, &BasicTunnel::TapReadComplete);
  tdev_->write_completion_.connect(this, &BasicTunnel::TapWriteComplete);
}

void
BasicTunnel::Shutdown()
{
  net_worker_->Quit();
  sig_worker_->Quit();
  tdev_->Down();
  tdev_->Close();
}

unique_ptr<VirtualLink>
BasicTunnel::CreateVlink(
  unique_ptr<VlinkDescriptor> vlink_desc,
  unique_ptr<PeerDescriptor> peer_desc,
  cricket::IceRole ice_role)
{
  vlink_desc->stun_servers = descriptor_->stun_servers;
  vlink_desc->turn_descs = descriptor_->turn_descs;
  unique_ptr<VirtualLink> vl = make_unique<VirtualLink>(
    move(vlink_desc), move(peer_desc), sig_worker_, net_worker_);
  unique_ptr<SSLIdentity> sslid_copy(sslid_->Clone());
  vl->Initialize(net_manager_, move(sslid_copy), *local_fingerprint_.get(),
    ice_role);
  vl->SignalMessageReceived.connect(this, &BasicTunnel::VlinkReadComplete);
  vl->SignalLinkUp.connect(this, &BasicTunnel::VLinkUp);
  vl->SignalLinkDown.connect(this, &BasicTunnel::VLinkDown);
  if (vl->PeerCandidates().length() != 0)
    vl->StartConnections();

  return vl;
}

void
BasicTunnel::VLinkUp(
  string vlink_id)
{
  StartIo();
  unique_ptr<TincanControl> ctrl = make_unique<TincanControl>();
  ctrl->SetControlType(TincanControl::CTTincanRequest);
  Json::Value & req = ctrl->GetRequest();
  req[TincanControl::Command] = TincanControl::LinkStateChange;
  req[TincanControl::TunnelId] = descriptor_->uid;
  req[TincanControl::LinkId] = vlink_id;
  req[TincanControl::Data] = "LINK_STATE_UP";
  ctrl_link_->Deliver(move(ctrl));
}

void
BasicTunnel::VLinkDown(
  string vlink_id)
{
  //StopIo();
  unique_ptr<TincanControl> ctrl = make_unique<TincanControl>();
  ctrl->SetControlType(TincanControl::CTTincanRequest);
  Json::Value & req = ctrl->GetRequest();
  req[TincanControl::Command] = TincanControl::LinkStateChange;
  req[TincanControl::TunnelId] = descriptor_->uid;
  req[TincanControl::LinkId] = vlink_id;
  req[TincanControl::Data] = "LINK_STATE_DOWN";
  ctrl_link_->Deliver(move(ctrl));
}

void
BasicTunnel::StartIo()
{
  for(uint8_t i = 0; i < tp.kLinkConcurrentAIO; i++)
  {
    unique_ptr<TapFrame> tf = make_unique<TapFrame>();
    tf->Initialize();
    tf->BufferToTransfer(tf->Payload());
    tf->BytesToTransfer(tf->PayloadCapacity());
    if(0 == tdev_->Read(*tf))
      tf.release();
    else
      RTC_LOG(LS_ERROR) << "A TAP read operation failed to start!";
  }
}

TunnelDescriptor &
BasicTunnel::Descriptor()
{
  return *descriptor_.get();
}

string
BasicTunnel::Name()
{
  return descriptor_->uid;
}

string
BasicTunnel::MacAddress()
{
  MacAddressType mac = tdev_->MacAddress();
  return ByteArrayToString(mac.begin(), mac.end(), 0);
}

string
BasicTunnel::Fingerprint()
{
  return local_fingerprint_->ToString();
}

void
BasicTunnel::SetIgnoredNetworkInterfaces(
  const vector<string>& ignored_list)
{
  net_manager_.set_network_ignore_list(ignored_list);
}

void BasicTunnel::OnMessage(Message * msg)
{
  switch(msg->message_id)
  {
  case MSGID_TRANSMIT:
  {
    unique_ptr<TapFrame> frame = move(((TransmitMsgData*)msg->pdata)->frm);
    shared_ptr<VirtualLink> vl = ((TransmitMsgData*)msg->pdata)->vl;
    vl->Transmit(*frame);
    delete msg->pdata;
    frame->Initialize(frame->Payload(), frame->PayloadCapacity());
    if(0 == tdev_->Read(*frame))
      frame.release();
  }
  break;
  case MSGID_SEND_ICC:
  {
    unique_ptr<TapFrame> frame = move(((TransmitMsgData*)msg->pdata)->frm);
    shared_ptr<VirtualLink> vl = ((TransmitMsgData*)msg->pdata)->vl;
    vl->Transmit(*frame);
    //RTC_LOG(LS_INFO) << "Sent ICC to=" <<vl->PeerInfo().vip4 << " data=\n" <<
    //  string((char*)(frame->begin()+4), *(uint16_t*)(frame->begin()+2));
    delete msg->pdata;
  }
  break;
  case MSGID_QUERY_NODE_INFO:
  {
    shared_ptr<VirtualLink> vl = ((LinkInfoMsgData*)msg->pdata)->vl;
    vl->GetStats(((LinkInfoMsgData*)msg->pdata)->info);
    ((LinkInfoMsgData*)msg->pdata)->msg_event.Set();
  }
  break;
  case MSGID_FWD_FRAME:
  case MSGID_FWD_FRAME_RD:
  {
    unique_ptr<TapFrame> frame = move(((TransmitMsgData*)msg->pdata)->frm);
    shared_ptr<VirtualLink> vl = ((TransmitMsgData*)msg->pdata)->vl;
    vl->Transmit(*frame);
    //RTC_LOG(LS_INFO) << "FWDing frame to " << vl->PeerInfo().vip4;
    if(msg->message_id == MSGID_FWD_FRAME_RD)
    {
      frame->Initialize(frame->Payload(), frame->PayloadCapacity());
      if(0 == tdev_->Read(*frame))
        frame.release();
    }
    delete msg->pdata;
  }
  break;
  case MSGID_DISC_LINK:
  {
    shared_ptr<VirtualLink> vl = ((LinkMsgData*)msg->pdata)->vl;
    vl->Disconnect();
    ((LinkInfoMsgData*)msg->pdata)->msg_event.Set();
  }
  break;
  }
}

void
BasicTunnel::InjectFame(
  string && data)
{
  unique_ptr<TapFrame> tf = make_unique<TapFrame>();
  tf->Initialize();
  if(data.length() > 2 * tp.kTapBufferSize)
  {
    stringstream oss;
    oss << "Inject Frame operation failed - frame size " << data.length() / 2
      << " is larger than maximum accepted " << tp.kTapBufferSize;
    throw TCEXCEPT(oss.str().c_str());
  }
  size_t len = StringToByteArray(data, tf->Payload(), tf->End());
  if(len != data.length() / 2)
    throw TCEXCEPT("Inject Frame operation failed - ICC decode failure");
  tf->SetWriteOp();
  tf->PayloadLength((uint32_t)len);
  tf->BufferToTransfer(tf->Payload());
  tf->BytesTransferred((uint32_t)len);
  tf->BytesToTransfer((uint32_t)len);
  tdev_->Write(*tf.release());
  //RTC_LOG(LS_INFO) << "Frame injected=\n" << data;
}
} //namespace tincan
