# wireshark-plugin-afdx
#
# Copyright 2017 REDLAB-I, LLC <http://redlab-i.ru>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


project(wireshark-plugin-tftp2 C)
set(PROJECT_VERSION 0.1.0)

set(WERROR 1)

cmake_minimum_required(VERSION 2.6)

find_package(Wireshark)
if(NOT Wireshark_FOUND)
	message(FATAL_ERROR "No wireshark-dev found.")
endif(NOT Wireshark_FOUND)

list(APPEND CMAKE_MODULE_PATH "${Wireshark_CMAKE_MODULES_DIR}")

find_package(GLIB2)
if(NOT GLIB2_FOUND)
	message(FATAL_ERROR "No libglib2.0-dev found.")
endif(NOT GLIB2_FOUND)

include_directories(${GLIB2_INCLUDE_DIRS})
include_directories (${Wireshark_INCLUDE_DIR})

if(NOT CMAKE_INSTALL_LIBDIR)
	set(CMAKE_INSTALL_LIBDIR ${Wireshark_CMAKE_MODULES_DIR}/plugins/${Wireshark_VERSION_MAJOR}.${Wireshark_VERSION_MINOR}/epan)
endif(NOT CMAKE_INSTALL_LIBDIR)
message(STATUS "Plug-in will be installed to: ${CMAKE_INSTALL_LIBDIR}")


include_directories(${CMAKE_CURRENT_SOURCE_DIR})
set(PLUGIN_VERSION "${PROJECT_VERSION}")
add_definitions(-DPLUGIN_VERSION=\"${PLUGIN_VERSION}\")

set(DISSECTOR_SRC src/packet-tftp2.c)

set(DISSECTOR_EXTRA_SRC "")
set(PLUGIN_FILES plugin.c ${DISSECTOR_SRC} ${DISSECTOR_EXTRA_SRC})
set(CLEAN_FILES ${PLUGIN_FILES})

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
endif(WERROR)



include( UseMakePluginReg )
register_plugin_files(plugin.c plugin ${DISSECTOR_SRC} ${DISSECTOR_EXTRA_SRC})

set(LINK_MODE_LIB SHARED)
set(LINK_MODE_MODULE MODULE)
add_library(tftp2 ${LINK_MODE_MODULE} ${PLUGIN_FILES})
set_target_properties(tftp2 PROPERTIES PREFIX "")
set_target_properties(tftp2 PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")

install(TARGETS tftp2
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} NAMELINK_SKIP
)
