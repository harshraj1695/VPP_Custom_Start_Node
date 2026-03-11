#ifndef __included_tap_utils_h__
#define __included_tap_utils_h__

// ─────────────────────────────────────────────────────────────────────────────
// tap_utils.h
//
// Header for TAP interface helper functions.
// Declares the functions defined in tap_utils.c so other files can call them.
// ─────────────────────────────────────────────────────────────────────────────

#include <vlib/vlib.h>

// Opens a TAP interface by name and returns a file descriptor (fd).
// Returns -1 on failure.
// tap_name = name of the Linux TAP interface, e.g. "mytap0"
int tap_open_interface (const char *tap_name);

// Closes a TAP interface file descriptor.
// Safe to call even if fd is already -1.
void tap_close_interface (int fd);

#endif // __included_tap_utils_h__
