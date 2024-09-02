# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

configure_file(Doxyfile.in Doxyfile)
configure_file(conf.py.in conf.py)

file(COPY _static DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY _templates DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

set(doc_srcs
	index.rst overview.rst usage.rst reference.rst
	developers/build.rst developers/generation.rst developers/packets_processing.rst
	developers/fronts/index.rst developers/fronts/nftables.rst
)

get_target_property(shared_srcs shared SOURCES)
get_target_property(core_srcs core SOURCES)
get_target_property(lib_srcs lib SOURCES)
get_target_property(generator_srcs generator SOURCES)
get_target_property(xlate_srcs xlate SOURCES)

add_custom_target(doc
	COMMAND Doxygen::doxygen Doxyfile
	COMMAND ${SPHINX_BIN} -c . -Dbreathe_projects.bpfilter=xml ${CMAKE_CURRENT_SOURCE_DIR} html
	DEPENDS Doxyfile.in conf.py ${doc_srcs} ${shared_srcs} ${core_srcs} ${lib_srcs} ${generator_srcs} ${xlate_srcs}
	BYPRODUCTS xml html
	COMMENT "Generate HTML documentation"
)

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
