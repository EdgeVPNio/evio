#!/bin/bash

helpFunction()
{
        echo ""
        echo "Usage: $0 -b build_type -t target_os"
        echo -e "\t-b build_type can be release or debug"
        echo -e "\t-t target_os can be ubuntu or raspberry-pi"
        exit 1 # Exit script after printing help
}

while getopts b:t: opt
do
        case "$opt" in
                b ) build_type="$OPTARG" ;;
                t ) target_os="$OPTARG" ;;
                ? ) helpFunction ;; # Print helpFunction in case parameter is non-existent
        esac
done

# Print helpFunction in case parameters are empty
if [ -z "$build_type" ] || [ -z "$target_os" ]
then
        echo "Some or all of the parameters are empty";
        helpFunction
fi
if [ "$build_type" != "debug" ] && [ "$build_type" != "release" ]; then
        echo "Wrong build_type spelling"
        helpFunction
elif [ "$target_os" != "ubuntu" ] && [ "$target_os" != "raspberry-pi" ]; then
        echo "Wrong OS type spelling"
        helpFunction
fi

mkdir -p evio/external/Libs/$build_type
#getting the required .o files and .a files to 3rd party libs from webrtc-checkout
#build_type="$build_type"
llvm-ar -rcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/rtc_base/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/rtc_base_approved/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/p2p/rtc_p2p/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/logging/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/rtc_event/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/stringutils/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/timeutils/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/platform_thread_types/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/criticalsection/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/api/crypto/options/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/pc/rtc_pc_base/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/checks/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/synchronization/sequence_checker/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/synchronization/yield_policy/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/api/rtc_error/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/system_wrappers/metrics/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/system_wrappers/field_trial/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/logging/ice_log/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/experiments/field_trial_parser/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/api/transport/stun_types/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/api/libjingle_peerconnection_api/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/weak_ptr/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/network/sent_packet/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/rtc_numerics/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/third_party/base64/base64/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/api/task_queue/task_queue/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/system/file_wrapper/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/rtc_base/platform_thread/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/api/rtc_event_log/rtc_event_log/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/api/rtp_parameters/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/api/transport/media/media_transport_interface/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/call/rtp_receiver/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/modules/rtp_rtcp/rtp_rtcp_format/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/media/rtc_media_base/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/api/units/data_size/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/api/units/time_delta/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/api/units/data_rate/*.o
llvm-ar -qcs external/$build_type/libwebrtc_lite.a webrtc-checkout/src/out/$build_type/obj/api/video/video_rtp_headers/*.o
#archives from third-party directory
llvm-ar -rcs external/$build_type/libboringssl_asm.a webrtc-checkout/src/out/$build_type/obj/third_party/boringssl/boringssl_asm/*.o
llvm-ar -qcs external/$build_type/libjsoncxx.a webrtc-checkout/src/out/$build_type/obj/third_party/jsoncpp/jsoncpp/json_reader.o webrtc-checkout/src/out/$build_type/obj/third_party/jsoncpp/jsoncpp/json_value.o webrtc-checkout/src/out/$build_type/obj/third_party/jsoncpp/jsoncpp/json_writer.o
llvm-ar -rcs external/$build_type/libboringssl.a webrtc-checkout/src/out/$build_type/obj/third_party/boringssl/boringssl/*.o
llvm-ar -rcs external/$build_type/libprotobuf_lite.a webrtc-checkout/src/out/$build_type/obj/third_party/protobuf/protobuf_lite/*.o
llvm-ar -qcs external/$build_type/libabseil-cpp.a webrtc-checkout/src/out/$build_type/obj/third_party/abseil-cpp/absl/strings/strings/*.o  webrtc-checkout/src/out/$build_type/obj/third_party/abseil-cpp/absl/base/throw_delegate/*.o webrtc-checkout/src/out/$build_type/obj/third_party/abseil-cpp/absl/types/bad_optional_access/*.o webrtc-checkout/src/out/$build_type/obj/third_party/abseil-cpp/absl/base/raw_logging_internal/*.o
llvm-ar -rcs external/$build_type/libsrtp.a webrtc-checkout/src/out/$build_type/obj/third_party/libsrtp/libsrtp/*.o
llvm-ar -rcs external/$build_type/libc++.a webrtc-checkout/src/out/$build_type/obj/buildtools/third_party/libc++/libc++/*.o
llvm-ar -rcs external/$build_type/libc++abi.a webrtc-checkout/src/out/$build_type/obj/buildtools/third_party/libc++abi/libc++abi/*.o
