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
#include "tincan_control.h"
#include "rtc_base/logging.h"
#include "tincan_exception.h"
namespace tincan
{
extern TincanParameters tp;
const Json::StaticString TincanControl::Command("Command");
const Json::StaticString TincanControl::CAS("CAS");
const Json::StaticString TincanControl::ControlType("ControlType");
const Json::StaticString TincanControl::Controlled("Controlled");
const Json::StaticString TincanControl::Controlling("Controlling");
const Json::StaticString TincanControl::CreateCtrlRespLink("CreateCtrlRespLink");
const Json::StaticString TincanControl::CreateTunnel("CreateTunnel");
const Json::StaticString TincanControl::Data("Data");
const Json::StaticString TincanControl::Echo("Echo");
const Json::StaticString TincanControl::EncryptionEnabled("EncryptionEnabled");
const Json::StaticString TincanControl::FPR("FPR");
const Json::StaticString TincanControl::ICC("ICC");
const Json::StaticString TincanControl::IceRole("IceRole");
const Json::StaticString TincanControl::IgnoredNetInterfaces("IgnoredNetInterfaces");
const Json::StaticString TincanControl::IP4PrefixLen("IP4PrefixLen");
const Json::StaticString TincanControl::EVIO("EVIO");
const Json::StaticString TincanControl::LinkId("LinkId");
const Json::StaticString TincanControl::LinkStateChange("LinkStateChange");
const Json::StaticString TincanControl::Level("Level");
const Json::StaticString TincanControl::MAC("MAC");
const Json::StaticString TincanControl::Message("Message");
const Json::StaticString TincanControl::MTU4("MTU4");
const Json::StaticString TincanControl::NodeId("NodeId");
const Json::StaticString TincanControl::PeerInfo("PeerInfo");
const Json::StaticString TincanControl::ProtocolVersion("ProtocolVersion");
const Json::StaticString TincanControl::QueryTunnelInfo("QueryTunnelInfo");
const Json::StaticString TincanControl::QueryCandidateAddressSet("QueryCandidateAddressSet");
const Json::StaticString TincanControl::RemoveTunnel("RemoveTunnel");
const Json::StaticString TincanControl::ReqRouteUpdate("ReqRouteUpdate");
const Json::StaticString TincanControl::Request("Request");
const Json::StaticString TincanControl::Response("Response");
const Json::StaticString TincanControl::Role("Role");
const Json::StaticString TincanControl::SetIgnoredNetInterfaces("SetIgnoredNetInterfaces");
const Json::StaticString TincanControl::SetLoggingLevel("SetLoggingLevel");
const Json::StaticString TincanControl::Stats("Stats");
const Json::StaticString TincanControl::Status("Status");
const Json::StaticString TincanControl::Success("Success");
const Json::StaticString TincanControl::TapName("TapName");
const Json::StaticString TincanControl::TincanRequest("TincanRequest");
const Json::StaticString TincanControl::TincanResponse("TincanResponse");
const Json::StaticString TincanControl::TransactionId("TransactionId");
const Json::StaticString TincanControl::TunnelId("TunnelId");
const Json::StaticString TincanControl::Type("Type");
const Json::StaticString TincanControl::UID("UID");
const Json::StaticString TincanControl::UpdateRouteTable("UpdateRouteTable");
const Json::StaticString TincanControl::VIP4("VIP4");
const Json::StaticString TincanControl::VnetDescription("VnetDescription");
const Json::StaticString TincanControl::Vlinks("Vlinks");

TincanControl::TincanControl() :
  proto_ver_(tp.kTincanControlVer),
  tag_(NextTagValue()),
  type_(CTTincanRequest),
  dict_req_(nullptr),
  dict_resp_(nullptr)
{}

TincanControl::TincanControl(
  unique_ptr<Json::Value> req) :
  proto_ver_(tp.kTincanControlVer),
  tag_(NextTagValue()),
  type_(CTTincanRequest),
  dict_req_(req.release()),
  dict_resp_(new Json::Value(Json::objectValue))
{}

TincanControl::TincanControl(
  unique_ptr<Json::Value> req,
  unique_ptr<Json::Value> resp) :
  proto_ver_(tp.kTincanControlVer),
  tag_(NextTagValue()),
  type_(CTTincanRequest),
  dict_req_(req.release()),
  dict_resp_(resp.release())
{}

TincanControl::TincanControl(
  const char * const req_data,
  const size_t len) :
  dict_req_(new Json::Value(Json::objectValue)),
  dict_resp_(new Json::Value(Json::objectValue))
{
  //create Json from full request
  Json::CharReaderBuilder b;
  Json::CharReader* parser = b.newCharReader();
  Json::String errs;
  Json::Value ctrl(Json::objectValue);
  if(!parser->parse(req_data, req_data + len, &ctrl, &errs))
  {
    string errmsg = "Unable to parse json control object - ";
    errmsg.append(req_data, req_data + len);
    throw TCEXCEPT(errmsg.c_str());
  }
  if(ctrl[EVIO].isNull() || ctrl[EVIO].empty())
  {
    ostringstream oss;
    oss << "The control is invalid, the'EVIO' header is missing" << endl
      << req_data;
    throw TCEXCEPT(oss.str().c_str());
  }
  uint32_t ver = ctrl[EVIO][ProtocolVersion].asUInt();
  if(ver != tp.kTincanControlVer)
  {
    ostringstream oss;
    oss << "Invalid EVIO protocol version in control header (" << ver << ")";
    throw TCEXCEPT(oss.str().c_str());
  }
  proto_ver_ = ver;
  string ct = ctrl[EVIO][ControlType].asString();
  if(ct == ControlTypeStrings[CTTincanRequest])
  {
    type_ = CTTincanRequest;
  }
  else if(ct == ControlTypeStrings[CTTincanResponse])
  {
    type_ = CTTincanResponse;
  }
  else
  {
    throw TCEXCEPT("Invalid control type");
  }
  tag_ = ctrl[EVIO][TransactionId].asInt64();
  if(ctrl[EVIO].isMember(Request))
  {
    Json::Value removed_mem;
    bool status = ctrl[EVIO].removeMember(Request, &removed_mem);
    if(status == true)
    	(*dict_req_) = removed_mem;    
  }
  if(ctrl[EVIO].isMember(Response)) {
    Json::Value removed_mem;
    bool status = ctrl[EVIO].removeMember(Response, &removed_mem);
    if(status == true)
    	(*dict_resp_) = removed_mem;    
  }
}

TincanControl::TincanControl(
  const TincanControl & ctrl_req) :
  proto_ver_(ctrl_req.proto_ver_),
  tag_(ctrl_req.tag_),
  type_(ctrl_req.type_),
  dict_req_(new Json::Value(*ctrl_req.dict_req_)),
  dict_resp_(new Json::Value(*ctrl_req.dict_resp_))
{}

TincanControl::TincanControl(
  TincanControl && ctrl_req) :
  proto_ver_(ctrl_req.proto_ver_),
  tag_(ctrl_req.tag_),
  type_(ctrl_req.type_),
  dict_req_(ctrl_req.dict_req_),
  dict_resp_(ctrl_req.dict_resp_)
{
  ctrl_req.dict_req_ = nullptr;
  ctrl_req.dict_resp_ = nullptr;
}

TincanControl::~TincanControl()
{
  delete dict_req_;
  delete dict_resp_;
}

TincanControl &
TincanControl::operator=(
  TincanControl & rhs)
{
  if(this != &rhs)
  {
    proto_ver_ = rhs.proto_ver_;
    tag_ = rhs.tag_;
    type_ = rhs.type_;

    delete dict_req_;
    dict_req_ = new Json::Value(*rhs.dict_req_);
    delete dict_resp_;
    dict_resp_ = new Json::Value(*rhs.dict_resp_);
  }
  return *this;
}

TincanControl &
TincanControl::operator=(
  TincanControl && rhs)
{
  if(this != &rhs)
  {
    proto_ver_ = rhs.proto_ver_;
    tag_ = rhs.tag_;
    type_ = rhs.type_;

    delete dict_req_;
    dict_req_ = rhs.dict_req_;
    rhs.dict_req_ = nullptr;
    delete dict_resp_;
    dict_resp_ = rhs.dict_resp_;
    rhs.dict_resp_ = nullptr;
  }
  return *this;
}

string
TincanControl::StyledString()
{
  Json::Value ctrl(Json::objectValue);
  ctrl[EVIO][ProtocolVersion] = proto_ver_;
  ctrl[EVIO][TransactionId] = (Json::UInt64)tag_;
  ctrl[EVIO][ControlType] = ControlTypeStrings[type_];
  if(dict_req_)
    ctrl[EVIO][Request] = *dict_req_;
  if(dict_resp_)
    ctrl[EVIO][Response] = *dict_resp_;
  return ctrl.toStyledString();
}

void TincanControl::SetRequest(unique_ptr<Json::Value> req)
{
  delete dict_req_;
  dict_req_ = req.release();
  type_ = CTTincanRequest;
}

Json::Value &
TincanControl::GetRequest()
{
  if(!dict_req_)
    dict_req_ = new Json::Value(Json::objectValue);
  return (*dict_req_);
}

void
TincanControl::SetResponse(
  unique_ptr<Json::Value> resp)
{
  delete dict_resp_;
  dict_resp_ = resp.release();
  type_ = CTTincanResponse;
}

void
TincanControl::SetResponse(
  const string & resp_msg,
  bool success)
{
  if(!dict_resp_)
    dict_resp_ = new Json::Value(Json::objectValue);
  (*dict_resp_)[Message] = resp_msg;
  (*dict_resp_)[Success] = success;
  type_ = CTTincanResponse;
}

Json::Value &
TincanControl::GetResponse()
{
  if(!dict_resp_)
    dict_resp_ = new Json::Value(Json::objectValue);
  return (*dict_resp_);
}

string
TincanControl::GetCommand() const
{
  if(type_ == CTTincanRequest)
    return (*dict_req_)[Command].asString();
  else if(type_ == CTTincanResponse)
    return (*dict_resp_)[Command].asString();
  return string();
}

void TincanControl::SetCommand(string cmd)
{
  if(type_ == CTTincanRequest)
    (*dict_req_)[Command] = cmd;
  else if(type_ == CTTincanResponse)
    (*dict_resp_)[Command] = cmd;
}

void TincanControl::SetTransactionId(uint64_t tag)
{
  (*dict_req_)[TransactionId] = (Json::UInt64)tag;
}

uint64_t
TincanControl::GetTransactionId() const
{
  return tag_;
}

TincanControl::ControlTypeEnum
TincanControl::GetControlType() const
{
  return type_;
}

void TincanControl::SetControlType(ControlTypeEnum type)
{
  type_ = type;
}

} // namespace tincan
