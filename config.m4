PHP_ARG_ENABLE(arp, Whether to enable ARP support Functions, [ --enable-arp
 Enable ARP Support ])

if test "$PHP_ARP" = "yes"; then
  AC_DEFINE(HAVE_ARP, 1, [Whether you have ARP Support])
  PHP_NEW_EXTENSION(arp, arp.c, $ext_shared)
fi

