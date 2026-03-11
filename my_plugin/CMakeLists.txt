# ─────────────────────────────────────────────────────────────────────────────
# CMakeLists.txt
#
# Build file for the my_plugin VPP plugin.
#
# HOW TO BUILD:
#   Place this entire my_plugin/ folder inside:
#     <vpp-source>/src/plugins/
#
#   Then build VPP normally:
#     cd <vpp-source>
#     make build
#
#   Or build just this plugin (faster during development):
#     cd <vpp-source>/build-root
#     make PLATFORM=vpp TAG=debug my_plugin-install
# ─────────────────────────────────────────────────────────────────────────────

# add_vpp_plugin() is a VPP-provided CMake macro that handles all the
# boilerplate of building a .so plugin file, installing it, etc.
add_vpp_plugin(my_plugin

  # List every .c file that is part of this plugin
  SOURCES
    my_plugin.c          # plugin init + global state
    tap_utils.c          # TAP open/close helpers
    my_start_node.c      # INPUT node - reads from TAP
    your_parser_node.c   # INTERNAL node - parses Ethernet headers
    your_firewall_node.c # INTERNAL node - applies IP block rules
    your_output_node.c   # INTERNAL node - final output / write back to TAP

  # List header files that should be installed with the plugin
  # (so other plugins can include them if needed)
  INSTALL_HEADERS
    my_start_node.h
    tap_utils.h

  # List the .api file so VPP generates the API bindings
  API_FILES
    my_plugin.api
)
