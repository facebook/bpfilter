# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

#[[
	Generate bpfilter's documentation

	The documentation is generated using:
	- Doxygen: parse the source files for Doxygen comments and generate XML
	  files containing the technical documentation.
	- Breathe: Sphinx plugin to print Doxygen documentation from a Sphinx
	  project.
	- Sphinx: documentation generate. Creates a documentation website from
	  the technical documentation provided by Breathe and the documentation
	  files under the "doc" directory.

	Usage of GLOB_RECURSE is not recommended because if a new source file is
	added to the project, there is no CMakeLists.txt file to update. If no
	CMakeLists.txt is updated, CMake doesn't know it needs to refresh the
	computed sources list. This is not an issue here, as the source file will
	be added to src/CMakeLists.txt anyway (no GLOB_RECURSE used there). Using
	GLOB_RECURSE prevents developers from forgetting about adding it to the
	documentation's dependencies.

	Warnings emitted by Doxygen during the XML generation or Sphinx during the
	HTML generation will be treated as errors. Those warnings are useful as
	they usually refer to an invalid Doxygen tax, it's a quick fix that helps
	to increase the documentation's quality.

	Doxygen's configuration file is version-specific. The approach taken here is
	to use Doxygen to generate the default configuration in the build folder,
	then include this default version in the project's Doxyfile and override
	relevant settings.

	Logs printed on the standard output for the commands defined below are
	suppressed to catch actual issues more easily.
#]]

file(GLOB_RECURSE bf_srcs
	${CMAKE_SOURCE_DIR}/src/*.c
	${CMAKE_SOURCE_DIR}/src/*.h
)

# Remove src/external/.* files from the list of sources
list(FILTER bf_srcs EXCLUDE REGEX "${CMAKE_SOURCE_DIR}/src/external/.*")

set(doc_srcs
	${CMAKE_CURRENT_SOURCE_DIR}/index.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/bfcli.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/daemon.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/index.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/iptables.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/nftables.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/build.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/generation.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/packets_processing.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/style.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/modules/index.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/modules/bpfilter.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/fronts/index.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/fronts/nftables.rst
)

configure_file(Doxyfile.in Doxyfile)
configure_file(conf.py.in conf.py)

add_custom_command(
	COMMAND Doxygen::doxygen -s -g ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.base >/dev/null
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.base
	COMMENT "Generating Doxyfile.base configuration"
)

add_custom_command(
	COMMAND Doxygen::doxygen ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
	DEPENDS
		${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
		${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.base
		${bf_srcs}
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/xml/index.xml
	COMMENT "Generating Doxygen XML documentation"
)

add_custom_command(
	COMMAND
		${CMAKE_COMMAND}
			-E copy_directory_if_different
			${CMAKE_CURRENT_SOURCE_DIR}/_static
			${CMAKE_CURRENT_BINARY_DIR}/_static
	COMMAND
		${CMAKE_COMMAND}
			-E copy_directory_if_different
			${CMAKE_CURRENT_SOURCE_DIR}/_templates
			${CMAKE_CURRENT_BINARY_DIR}/_templates
	COMMAND
		${SPHINX_BIN}
			-W 				# Return non-zero if a warning is triggered...
			--keep-going	# ... but don't stop as soon as there is a warning.
			-q				# Quiet.
			--jobs auto		# Use multiple cores.
			-c ${CMAKE_CURRENT_BINARY_DIR}
			${CMAKE_CURRENT_SOURCE_DIR}
			${CMAKE_CURRENT_BINARY_DIR}/html
			${doc_srcs}
	DEPENDS
		${CMAKE_CURRENT_BINARY_DIR}/conf.py
		${CMAKE_CURRENT_BINARY_DIR}/xml/index.xml
		${doc_srcs}
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/html/index.html
	COMMENT "Generating the documentation"
)

add_custom_target(doc DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/html/index.html)


#[[
	Compute unit tests code coverage and generate the HTML summary.
#]]

add_custom_target(coverage
	COMMAND ${LCOV_BIN} --capture --directory ${CMAKE_BINARY_DIR} --output-file lcov.out
	# Only keep the coverage for bpfilter's source files, not the tests.
	COMMAND ${LCOV_BIN}
		--output-file lcov.out
		--extract lcov.out
		--ignore-errors unused
		"${CMAKE_SOURCE_DIR}/src/\\*"
	COMMAND ${GENHTML_BIN} -o html_coverage lcov.out
	BYPRODUCTS html_coverage
	COMMENT "Generate coverage report"
)
