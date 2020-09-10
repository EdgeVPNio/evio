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
#include "control_dispatch.h"
#include "rtc_base/strings/json.h"
#include "tincan_exception.h"
#include "tunnel_descriptor.h"

namespace tincan
{
using namespace rtc;
ControlDispatch::ControlDispatch() :
  dtol_(nullptr),
  ctrl_link_(new DisconnectedControllerHandle())
{
  control_map_ = {
    { "ConfigureLogging", &ControlDispatch::ConfigureLogging },
    { "CreateCtrlRespLink", &ControlDispatch::CreateControllerRespLink },
    { "CreateLink", &ControlDispatch::CreateLink },
    { "CreateTunnel", &ControlDispatch::CreateTunnel },
    { "Echo", &ControlDispatch::Echo },
    { "SendIcc", &ControlDispatch::SendIcc },
    { "InjectFrame", &ControlDispatch::InjectFrame },
    { "QueryCandidateAddressSet", &ControlDispatch::QueryCandidateAddressSet },
    { "QueryLinkStats", &ControlDispatch::QueryLinkStats },
    { "QueryTunnelInfo", &ControlDispatch::QueryTunnelInfo },
    { "RemoveTunnel", &ControlDispatch::RemoveTunnel },
    { "RemoveLink", &ControlDispatch::RemoveLink },
    { "UpdateMap", &ControlDispatch::UpdateRouteTable },
  };
}
ControlDispatch::~ControlDispatch()
{
  LogMessage::RemoveLogToStream(log_sink_.get());
}

void
ControlDispatch::operator () (TincanControl & control)
{
  try {
    switch(control.GetControlType()) {
    case TincanControl::CTTincanRequest:
      (this->*control_map_.at(control.GetCommand()))(control);
      break;
    case TincanControl::CTTincanResponse:
    // todo: A controller response to something sent earlier
      break;
    default:
      RTC_LOG(LS_WARNING) << "Unrecognized control type received and discarded.";
      break;
    }
  }
  catch(out_of_range & e) {
    RTC_LOG(LS_WARNING) << "An invalid EVIO control operation was received and "
      "discarded: " << control.StyledString() << "Exception=" << e.what();
  }
  catch(exception & e)
  {
    RTC_LOG(LS_WARNING) << e.what();
  }
}
void
ControlDispatch::SetDispatchToTincanInf(
  TincanDispatchInterface * dtot)
{
  tincan_ = dtot;
}
void
ControlDispatch::SetDispatchToListenerInf(
  DispatchToListenerInf * dtol)
{
  dtol_ = dtol;
}

void
ControlDispatch::ConfigureLogging(
  TincanControl & control)
{
  Json::Value & req = control.GetRequest();
  string log_lvl = req[TincanControl::Level].asString();
  string msg("Tincan logging successfully configured.");
  bool status = true;
  try
  {
    ostringstream oss;
    std::transform(log_lvl.begin(), log_lvl.end(), log_lvl.begin(),
                   [=](char c) {return static_cast<char>(::tolower(c));});
    oss << "tstamp " << "thread " << log_lvl.c_str();
    LogMessage::ConfigureLogging(oss.str().c_str());
    LogMessage::LogToDebug(LS_WARNING);
    LogMessage::SetLogToStderr(true);
    if(req["Device"].asString() == "All" || req["Device"].asString() == "File")
    {
      LogMessage::SetLogToStderr(false);
      string dir = req["Directory"].asString();
      /*rtc::Pathname pn(dir);
      if(!Filesystem::IsFolder(pn))
        Filesystem::CreateFolder(pn);*/
      //TODO: uncomment below three lines and solve the issue with file_util.h header from webrtc
      // rtc::Pathname pn(dir);
      // FilePath pn(dir.GetPath().AppendASCII(req["Directory"].asString()));
      // if(!DirectoryExists(pn))
      //   CreateDirectory(pn);
      string fn = req["Filename"].asString();
      size_t max_sz = req["MaxFileSize"].asUInt64();
      size_t num_fls = req["MaxArchives"].asUInt64();
      log_sink_ = make_unique<FileRotatingLogSink>(dir, fn, max_sz, num_fls);
      log_sink_->Init();
      log_lvl = req[TincanControl::Level].asString();
      LogMessage::AddLogToStream(log_sink_.get(), GetLogLevel(log_lvl));
    }
    if(req["Device"].asString() == "All" ||
      req["Device"].asString() == "Console")
    {
      if(req["ConsoleLevel"].asString().length() > 0)
        log_lvl = req["ConsoleLevel"].asString();
      else if(req[TincanControl::Level].asString().length() > 0)
        log_lvl = req[TincanControl::Level].asString();
      LogMessage::LogToDebug(GetLogLevel(log_lvl));
      LogMessage::SetLogToStderr(true);
    }
  } catch(exception &)
  {
    LogMessage::LogToDebug(LS_WARNING);
    LogMessage::SetLogToStderr(true);
    msg = "The configure logging operation failed. Using Console/WARNING";
    RTC_LOG(LS_WARNING) << msg;
    status = false;
  }
  control.SetResponse(msg, status);
  ctrl_link_->Deliver(control);
}

void
ControlDispatch::CreateLink(
  TincanControl & control)
{
  Json::Value & req = control.GetRequest();
  string msg("Connection to peer node in progress.");
  bool status = false;
  lock_guard<mutex> lg(disp_mutex_);
  try
  {
    tincan_->CreateVlink(req, control);
    status = true;
  } catch(exception & e)
  {
    msg = "CreateLink failed.";
    RTC_LOG(LS_WARNING) << e.what() << ". Control Data=\n" <<
      control.StyledString();
  }
  if(!status)
  {
    control.SetResponse(msg, status);
    ctrl_link_->Deliver(control);
  } //else respond when CAS is available
}

void ControlDispatch::CreateControllerRespLink(
  TincanControl & control)
{
  Json::Value & req = control.GetRequest();
  string ip = req["IP"].asString();
  int port = req["Port"].asInt();
  string msg("Controller endpoint successfully created.");
  lock_guard<mutex> lg(disp_mutex_);
  try
  {
    unique_ptr<SocketAddress> ctrl_addr(new SocketAddress(ip, port));
    dtol_->CreateControllerLink(move(ctrl_addr));
    delete ctrl_link_;
    ctrl_link_ = &dtol_->GetControllerLink();
    tincan_->SetControllerLink(ctrl_link_);
    control.SetResponse(msg, true);
    ctrl_link_->Deliver(control);
  }
  catch(exception & e)
  {
    //if this fails we can't indicate this to the controller so log with
    //high severity
    RTC_LOG(LS_ERROR) << e.what() << ". Control Data=\n" <<
      control.StyledString();
  }
}

void
ControlDispatch::CreateTunnel(
  TincanControl & control)
{
  Json::Value & req = control.GetRequest();
  unique_ptr<Json::Value> resp = make_unique<Json::Value>(Json::objectValue);
  lock_guard<mutex> lg(disp_mutex_);
  try
  {
    tincan_->CreateTunnel(req, (*resp)["Message"]);
    (*resp)["Success"] = true;
  } catch(exception & e)
  {
    string er_msg = "The CreateTunnel operation failed.";
    RTC_LOG(LS_ERROR) << er_msg << e.what() << ". Control Data=\n" <<
      control.StyledString();
    (*resp)["Message"] = er_msg;
    (*resp)["Success"] = false;
  }
  control.SetResponse(move(resp));
  ctrl_link_->Deliver(control);
}

void ControlDispatch::Echo(TincanControl & control)
{
  Json::Value & req = control.GetRequest();
  string msg = req[TincanControl::Message].asString();
  control.SetResponse(msg, true);
  control.SetControlType(TincanControl::CTTincanResponse);
  ctrl_link_->Deliver(control);
}

LoggingSeverity
ControlDispatch::GetLogLevel(
  const string & log_level)
{
  LoggingSeverity lv = LS_WARNING;
  lock_guard<mutex> lg(disp_mutex_);
  if (log_level == "NONE")
    lv = rtc::LS_NONE;
  else if (log_level == "ERROR")
    lv = rtc::LS_ERROR;
  else if (log_level == "WARNING")
    lv = rtc::LS_WARNING;
  else if (log_level == "INFO" || log_level == "VERBOSE" || log_level == "DEBUG")
    lv = rtc::LS_INFO;
  else if (log_level == "LS_VERBOSE")
    lv = rtc::LS_VERBOSE;
  else
  {
    string msg = "An invalid log level was specified =  ";
    RTC_LOG(LS_WARNING) << msg << log_level << ". Defaulting to WARNING";
  }
  return lv;
}

void
ControlDispatch::InjectFrame(
  TincanControl & control)
{
  Json::Value & req = control.GetRequest();
  string msg = "InjectFrame failed.";
  bool status = false;
  lock_guard<mutex> lg(disp_mutex_);
  try
  {
    tincan_->InjectFrame(req);
    msg = "InjectFrame succeeded.";
    status = true;
  } catch(exception & e)
  {
    RTC_LOG(LS_WARNING) << e.what() << ". Control Data=\n" <<
      control.StyledString();
  }
  control.SetResponse(msg, status);
  ctrl_link_->Deliver(control);
}

void
ControlDispatch::QueryCandidateAddressSet(
  TincanControl & control)
{
  Json::Value & req = control.GetRequest(), cas_info;
  string resp;
  bool status = false;
  lock_guard<mutex> lg(disp_mutex_);
  try
  {
    tincan_->QueryLinkCas(req, cas_info);
    resp = cas_info.toStyledString();
    status = true;
  } catch(exception & e)
  {
    resp = "The QueryCandidateAddressSet operation failed. ";
    RTC_LOG(LS_WARNING) << resp << e.what() << ". Control Data=\n" <<
      control.StyledString();
  }
  control.SetResponse(resp, status);
  ctrl_link_->Deliver(control);
}

void
ControlDispatch::QueryLinkStats(
  TincanControl & control)
{
  Json::Value & req = control.GetRequest();
  unique_ptr<Json::Value> resp = make_unique<Json::Value>(Json::objectValue);
  (*resp)["Success"] = false;
  lock_guard<mutex> lg(disp_mutex_);
  try
  {
    tincan_->QueryLinkStats(req, (*resp)["Message"]);
    (*resp)["Success"] = true;
  } catch(exception & e)
  {
    string er_msg = "The QueryLinkStats operation failed. ";
    RTC_LOG(LS_WARNING) << er_msg << e.what() << ". Control Data=\n" <<
      control.StyledString();
    (*resp)["Message"] = er_msg;
    (*resp)["Success"] = false;
  }
  control.SetResponse(move(resp));
  ctrl_link_->Deliver(control);
}

void
ControlDispatch::QueryTunnelInfo(
  TincanControl & control)
{
  Json::Value & req = control.GetRequest(), node_info;
  string resp("The QueryTunnelInfo operation succeeded");
  bool status = false;
  lock_guard<mutex> lg(disp_mutex_);
  try
  {
    tincan_->QueryTunnelInfo(req, node_info);
    resp = node_info.toStyledString();
    status = true;
  } catch(exception & e)
  {
    resp = "The QueryTunnelInfo operation failed. ";
    resp.append(e.what());
    RTC_LOG(LS_WARNING) << resp << e.what() << ". Control Data=\n" <<
      control.StyledString();
  }
  control.SetResponse(resp, status);
  ctrl_link_->Deliver(control);
}


void
ControlDispatch::RemoveLink(
  TincanControl & control)
{
  bool status = false;
  Json::Value & req = control.GetRequest();
  string msg("The RemoveLink operation succeeded");
  lock_guard<mutex> lg(disp_mutex_);
  try
  {
    tincan_->RemoveVlink(req);
    status = true;
  } catch(exception & e)
  {
    msg = "The RemoveLink operation failed.";
    RTC_LOG(LS_WARNING) << e.what() << ". Control Data=\n" <<
      control.StyledString();
  }
  control.SetResponse(msg, status);
  ctrl_link_->Deliver(control);
}

void
ControlDispatch::RemoveTunnel(
  TincanControl & control)
{
  bool status = false;
  Json::Value & req = control.GetRequest();
  string msg("The RemoveTunnel operation ");
  lock_guard<mutex> lg(disp_mutex_);
  try
  {
    tincan_->RemoveTunnel(req);
    status = true;
    msg.append("succeeded.");
  } catch(exception & e)
  {
    msg = "failed.";
    RTC_LOG(LS_WARNING) << e.what() << ". Control Data=\n" <<
      control.StyledString();
  }
  control.SetResponse(msg, status);
  ctrl_link_->Deliver(control);
}

void
ControlDispatch::SendIcc(
  TincanControl & control)
{
  Json::Value & req = control.GetRequest();
  string msg("The ICC operation succeeded");
  lock_guard<mutex> lg(disp_mutex_);
  try
  {
    tincan_->SendIcc(req);
  } catch(exception & e)
  {
    msg = "The ICC operation failed.";
    RTC_LOG(LS_WARNING) << e.what() << ". Control Data=\n" <<
      control.StyledString();
    control.SetResponse(msg, false);
    ctrl_link_->Deliver(control);
  }
}

void
ControlDispatch::UpdateRouteTable(
  TincanControl & control)
{
  bool status = false;
  Json::Value & req = control.GetRequest();
  string msg = "The Add Routes operation failed.";
  lock_guard<mutex> lg(disp_mutex_);
  try
  {
    tincan_->UpdateRouteTable(req);
    status = true;
    msg = "The Add Routes opertation completed successfully.";
  } catch(exception & e)
  {
    RTC_LOG(LS_WARNING) << e.what() << ". Control Data=\n" <<
      control.StyledString();
  }
  control.SetResponse(msg, status);
  ctrl_link_->Deliver(control);
}
}  // namespace tincan
