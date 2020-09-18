#!/bin/bash

#getting the required include files and folders from webrtc-checkout
# folders required: absl,api,base,call,common_video,logging,media,modules,p2p,pc,system_wrappers,rtc_base,build,common_types.h, jni.h, logging_buildflags.h
mkdir -p  external/include
cp -r webrtc-checkout/src/third_party/abseil-cpp/absl external/include
cp -r webrtc-checkout/src/api external/include
cp -r webrtc-checkout/src/base external/include
cp -r webrtc-checkout/src/call external/include
cp -r webrtc-checkout/src/common_video external/include
cp -r webrtc-checkout/src/logging external/include
cp -r webrtc-checkout/src/media external/include
cp -r webrtc-checkout/src/modules external/include
cp -r webrtc-checkout/src/p2p external/include
cp -r webrtc-checkout/src/pc external/include
cp -r webrtc-checkout/src/system_wrappers external/include
cp -r webrtc-checkout/src/rtc_base external/include
cp -r webrtc-checkout/src/third_party/jsoncpp/source/include/json external/include
cp webrtc-checkout/src/third_party/jsoncpp/generated/version.h external/include/json
cp webrtc-checkout/src/common_types.h external/include
cp webrtc-checkout/src/third_party/ffmpeg/libavcodec/jni.h external/include
mkdir -p /external/include/build && cp webrtc-checkout/src/build/build_config.h "$_"
cp webrtc-checkout/src/build/buildflag.h /external/include/build
