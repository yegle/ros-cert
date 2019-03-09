# ros-cert
A tool to get Let's Encrypt certificate on Mikrotik RouterBoard devices.

__NOTE__: this is a work-in-progress. Use at your own risk.

## Do you really need this?

Think before you use this tool. Most likely the webfig UI of your
RouterOS should not be publicly visible (i.e. only accessible from a
particular VLAN etc.). You probably don't need this.

## What does this tool do?

This tool is *NOT* a glorified SSH copy script that requires you to run
certbot or some other tools. It's an end-to-end tool to get a
certificate from Let's Encrypt, copy to your router, and set the
certificate correctly.

Prerequisite to use this tool:

1. You already have a domain that point to your router and you want to
   add the corresponding SSL certificate.
2. You have a computer that can access to your RouterOS's API service
   port (to run command) and SSH port (to copy certificate to the
   router).
