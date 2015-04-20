# PECL php-arp

A simple module to manipulate ip and mac requests though the ioctl interface of OpenBSD.

The module currently supports the following calls
 * `arp_get_mac(ip_str)` Get the mac address associated with the provided IP (if any). 
