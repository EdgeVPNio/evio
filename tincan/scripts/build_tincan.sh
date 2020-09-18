#!/bin/bash

#basic parameter checks on script
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
#for gn cmd
debug_flag=false
if [ "$build_type" == "debug" ]; then
        $debug_flag = true;
fi

#download and install dependencies
python_version="python3"
psutil_version=5.6.3
sleekxmpp_version=1.3.3
requests_version=2.21.0
simplejson_version=3.16.0
ryu_version=4.30
sudo apt update -y
sudo apt install -y git make libssl-dev g++-5 $python_version $python_version-pip $python_version-dev openvswitch-switch iproute2 bridge-utils
sudo -H $python_version -m pip install --upgrade pip
sudo -H $python_version -m pip --no-cache-dir install psutil==$psutil_version sleekxmpp==$sleekxmpp_version requests==$requests_version simplejson==$simplejson_version ryu==$ryu_version

mkdir -p ~/workspace
cd ~/workspace
git clone https://github.com/EdgeVPNio/evio.git
git clone -b ubuntu-x64 --single-branch https://github.com/EdgeVPNio/external.git tincan/external/
cd evio/tincan
if [[ "$target_os" == "ubuntu" ]]; then
	gn gen ../out/$build_type "--args='enable_iterator_debugging=false is_component_build=false is_debug=$debug_flag treat_warnings_as_errors=false use_lld=true target_sysroot_dir=\"/path/to/external/sysroot\"'"
else
        gn gen out/$build_type "--args='target_os=\"linux\" target_cpu=\"arm\" is_debug=$debug_flag treat_warnings_as_errors=false use_lld=true target_sysroot_dir=\"/path/to/external/sysroot\" enable_iterator_debugging=false is_component_build=false is_debug=true rtc_build_wolfssl=true rtc_build_ssl=false rtc_ssl_root=\"/usr/local/include\"\'"
fi

ninja -C ../out/$build_type tincan
