# SDWN agent feed repository for LEDE/OpenWRT

This is the SDWN agent source code to be used in conjunction with the [SDWN Controller for ONOS](https://github.com/berlin-open-wireless-lab/sdwn-controller)

## Installation

Add this to ```feeds.conf``` in your LEDE/OpenWRT source tree:
```
src-git sdwnagent https://github.com/berlin-open-wireless-lab/sdwn-agent
```
and run
```
scripts/feeds update sdwnagent && scripts/feeds install wlanflow
```
Next, run 
```
make menuconfig
```
and select the ```wlanflow``` package under _Network_.

## Configuration

Wlanflow is configured using UCI:

```
#/etc/config/sdwn

config controller 'name'
  option ipaddr '1.2.3.4'
  option port 6633
  option ubuspath '/path/to/ubus/socket'
```

### Config Options
1. ```ipaddr``` - the address of the ONOS controller.
2. ```port``` - the port of the controller's southbound OpenFlow interface (defaults to 6633).
3. ```ubuspath``` - optional parameter to direct the agent to the ubus socket within LEDE/OpenWRT.

The options in the config file can be overwritten on the command-line. Run ```wlanflow --help``` to see the syntax.

## Running the Agent

Wlanflow is intended to be run as a service using procd. You can start it, stop it, and trigger a config file reload by running
```/etc/init.d/wlanflow start/stop/reload```.
