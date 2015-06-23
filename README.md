# PECL php-arp

A simple module to manipulate ip and mac requests though the sysctl interface 
of OpenBSD. 

This module can be helpfull in situations where you cannot exec/fork an extrernal shell command (eg to run `arp`), such as `chroot` environments.

The module currently supports the following call
 * `arp_get_mac(ip_str)` Get the mac address associated with the provided IP 
 (if any). 

# Installation
First install the required packages to compile the module
```
pkg_add -vvi autoconf-2.69p1
```

Download the release appropriate to your system
```
git clone git@github.com:echothrust/pecl-arp.git
cd arp-pecl
AUTOCONF_VERSION=2.69 phpize-5.5
./configure --enable-arp --with-php-config=/usr/local/bin/php-config-5.5
make
sudo make install
echo "extension=arp.so" > /etc/php-5.5.sample/arp.ini
ln -sf /etc/php-5.5.sample/arp.ini /etc/php-5.5/arp.ini
```

Restart the php-fpm server

```
/etc/rc.d/php_fpm restart
```

