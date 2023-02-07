/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#ifndef NET_BPFILTER_LOGGER_H
#define NET_BPFILTER_LOGGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#define _BFLOG_IMPL(level, fmt, ...)					      \
	do {								      \
		typeof(level) __level = level;				      \
		if (logger_get_file()) {				      \
			fprintf(logger_get_file(), "<%d>bpfilter: " fmt "\n", \
				(__level), ##__VA_ARGS__);		      \
		}							      \
		if ((__level) == LOG_EMERG)				      \
			exit(EXIT_FAILURE);				      \
	} while (0)

#define BFLOG_EMERG(fmt, ...) \
	_BFLOG_IMPL(LOG_KERN | LOG_EMERG, fmt, ##__VA_ARGS__)
#define BFLOG_ERR(fmt, ...) \
	_BFLOG_IMPL(LOG_KERN | LOG_ERR, fmt, ##__VA_ARGS__)
#define BFLOG_NOTICE(fmt, ...) \
	_BFLOG_IMPL(LOG_KERN | LOG_NOTICE, fmt, ##__VA_ARGS__)

#ifdef DEBUG
#define BFLOG_DBG(fmt, ...) BFLOG_IMPL(LOG_KERN | LOG_DEBUG, fmt, ##__VA_ARGS__)
#else
#define BFLOG_DBG(fmt, ...)
#endif

#define STRERR(v) strerror(abs(v))

/**
 * logger_init() - Initialise logging facility.
 *
 * This function is used to open a file to write logs to (see @log_file_path).
 * It must be called before using any logging macro, otherwise log messages
 * will be discarded.
 *
 * Return: 0 on success, negative errno value on error.
 */
int logger_init(void);

/**
 * logger_set_file() - Set the FILE pointer to use to log messages.
 * @file: new FILE * to the log file.
 *
 * This function won't check whether the FILE pointer is valid, nor whether
 * a file is already opened, this is the responsibility of the caller. Once
 * logger_set_file() returns, all new log messages will be printed to the
 * FILE * provided.
 */
void logger_set_file(FILE *file);

/**
 * logger_get_file() - Returns a FILE * pointer to the log file.
 *
 * Return: pointer to the file to log to (as a FILE *), or NULL if the file
 *	is not valid.
 */
FILE *logger_get_file(void);

/**
 * logger_clean() - Close the log file.
 *
 * On success, the log file pointer will be NULL. If the function fails,
 * the log file pointer remain unchanged and the file should be considered open.
 *
 * Return: 0 on success, negative errno value on error.
 */
int logger_clean(void);

#endif // NET_BPFILTER_LOGGER_H
