# RIPster
_Super lightweight RIPv2 beacon_

RIPster is a lightweight, easy to use, single binary Routing Information Protocol version 2 (RIPv2) client written in Go.
RIPster advertises static or Docker Ipvlan L3 routes from the end-host, using the RIPv2 unsolicited routing update messages. RIPster does not receive RIP updates or alter the local routing table.

## Download

[Linux (32 bit)](https://github.com/jamsix/RIPster/raw/master/bin/ripster-linux-386)
[Linux (64 bit)](https://github.com/jamsix/RIPster/raw/master/bin/ripster-linux-amd64)
[macOS](https://github.com/jamsix/RIPster/raw/master/bin/ripster-windows)
[Windows](https://github.com/jamsix/RIPster/raw/master/bin/ripster-windows)

## Usage

RIPster must run with sufficient permissions to bind on UDP port 520. If unsure, use sudo.

### Advertise static routes

```$ sudo ./ripster --static-routes=7.7.0.0/16
2016-06-21 21:39:12  INFO   Adding 7.7.0.0/16 from 10.0.0.100 (static)
2016-06-21 21:39:12  INFO   RIP triggered update
2016-06-21 21:39:12  INFO   RIP advertising from 10.0.0.100: 7.7.0.0/16 (1)
```

### Advertise Docker ipvlan L3 routes

RIPster can advertise Docker [ipvlan network driver](https://github.com/docker/docker/blob/master/experimental/vlan-networks.md) routes, when ipvlan network is in L3 mode. You should run RIPster on Docker host. RIPster then queries Docker API to fetch the list of all ipvlan networks. RIPster then advertises all ipvlan networks and all running containers with an IP address in in ipvlan network from the ipvlan parent interface.

```$ sudo ./ripster --docker-ipvlan
2016-06-21 22:03:06  INFO   Adding 10.50.10.0/24 from 10.0.0.100  (Docker Ipvlan L3)
2016-06-21 22:03:06  INFO   Adding 10.50.10.2/32 from 10.0.0.100  (Docker Ipvlan L3)
2016-06-21 22:03:06  INFO   RIP triggered update
2016-06-21 22:03:06  INFO   RIP advertising from 10.0.0.100 : 10.50.10.0/24 (1) 10.50.10.2/32 (1)
```

### More Options

```$ sudo ./ripster -h
```

