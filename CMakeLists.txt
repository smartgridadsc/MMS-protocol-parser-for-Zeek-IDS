
cmake_minimum_required(VERSION 2.8)

project(BroPluginMMS)

include(BroPlugin)

bro_plugin_begin(Bro MMS)
bro_plugin_cc(src/MMS.cc src/Plugin.cc)
bro_plugin_bif(src/events.bif)
bro_plugin_pac(
	src/mms.pac 
	src/mms-analyzer.pac 
	src/mms-protocol.pac 
	src/mms-asn1.pac
	)
bro_plugin_dist_files(README CHANGES COPYING VERSION)
bro_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
