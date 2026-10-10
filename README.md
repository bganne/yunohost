# Yunohost deployment playground

Here I maintain the script I use to deploy [Yunohost](https://yunohost.org/) on my system.
A few specifics:
 - it is deployed in an unprivileged LXC container
 - DNS, firewall and backups are done on the host instead
 - the host monitors the UPS (NUT, shutdown on low battery) and graphs
   system stats with munin, served by nginx on http://<host>/munin/

## Quickstart

Build & start the VM:
```
~# make run
```

Run the VM provisioning (only need to be done once):
```
~# make provision
```

Enjoy :)
```
~# make ssh
```
