// ─────────────────────────────────────────────────────────────────────────────
// tap_utils.c
//
// Helper functions for opening and closing a Linux TAP interface.
//
// A TAP interface is a virtual Ethernet device in Linux.
// When you write to it → packets appear on the Linux side.
// When you read from it → you get packets that Linux sent.
//
// HOW TO CREATE THE TAP BEFORE RUNNING VPP:
//   sudo ip tuntap add dev mytap0 mode tap
//   sudo ip link set mytap0 up
//   sudo ip addr add 10.0.0.1/24 dev mytap0
// ─────────────────────────────────────────────────────────────────────────────

#include <fcntl.h>          // open(), O_RDWR, O_NONBLOCK
#include <unistd.h>         // close(), read()
#include <sys/ioctl.h>      // ioctl() - used to configure the TAP device
#include <linux/if.h>       // struct ifreq - holds interface settings
#include <linux/if_tun.h>   // IFF_TAP, IFF_NO_PI, TUNSETIFF
#include <string.h>         // strncpy
#include <vppinfra/format.h>// clib_warning() - VPP's logging function

#include "tap_utils.h"

// ─────────────────────────────────────────────────────────────────────────────
// tap_open_interface
//
// Opens the TAP interface named `tap_name`.
// Returns the file descriptor (a positive integer) on success.
// Returns -1 if anything goes wrong.
// ─────────────────────────────────────────────────────────────────────────────
int
tap_open_interface (const char *tap_name)
{
    // struct ifreq is a Linux struct used to set/get interface properties
    struct ifreq ifr;
    int fd;

    // Step 1: Open /dev/net/tun
    // This is the special Linux file that lets programs create TUN/TAP devices.
    // O_RDWR = open for both reading (receive) and writing (transmit)
    // O_NONBLOCK = don't block if no packet is ready, return immediately instead
    fd = open ("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0)
    {
        clib_warning ("tap_open_interface: failed to open /dev/net/tun");
        return -1;
    }

    // Step 2: Zero out ifr so there's no leftover garbage in memory
    memset (&ifr, 0, sizeof (ifr));

    // Step 3: Set the flags for what kind of interface we want:
    //   IFF_TAP   = we want TAP mode (Ethernet frames), not TUN (IP packets)
    //   IFF_NO_PI = don't prepend a 4-byte "Packet Info" header to each packet
    //               This keeps our packets clean - just raw Ethernet data
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    // Step 4: Set the interface name we want to attach to
    // IFNAMSIZ is the max length for an interface name (usually 16 bytes)
    strncpy (ifr.ifr_name, tap_name, IFNAMSIZ - 1);

    // Step 5: Apply the settings using ioctl()
    // TUNSETIFF = "TUN Set Interface Flags" - tells the kernel our desired config
    if (ioctl (fd, TUNSETIFF, &ifr) < 0)
    {
        clib_warning ("tap_open_interface: ioctl TUNSETIFF failed for '%s'",
                      tap_name);
        close (fd);  // always close the fd if we fail, to avoid fd leaks
        return -1;
    }

    clib_warning ("tap_open_interface: '%s' opened OK (fd=%d)", tap_name, fd);
    return fd;  // success! caller can now read() and write() on this fd
}

// ─────────────────────────────────────────────────────────────────────────────
// tap_close_interface
//
// Closes the TAP file descriptor.
// Safe to call with fd = -1 (does nothing in that case).
// ─────────────────────────────────────────────────────────────────────────────
void
tap_close_interface (int fd)
{
    if (fd >= 0)
    {
        close (fd);
        clib_warning ("tap_close_interface: closed fd=%d", fd);
    }
}
