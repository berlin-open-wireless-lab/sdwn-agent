# SDWN agent feed repository for LEDE/OpenWRT

This is the SDWN agent source code to be used in conjunction with the [SDWN ONOS Controller Application](https://github.com/berlin-open-wireless-lab/sdwn-onos)

## Installation

Add this to your ```feeds.conf``` in your LEDE/OpenWRT source tree:
```
src-git sdwnagent https://github.com/berlin-open-wireless-lab/sdwn-agent
```
and run
```
scripts/feeds update sdwnagent && scripts/feeds install wlanflow
```
Next, select the package running
```
make menuconfig
```
and ticking the box under _Network_.
