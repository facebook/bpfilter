// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "logger.h"

#include <errno.h>

static const char *log_file_path = "/dev/kmsg";
static FILE *log_file;

int logger_init(void)
{
	if (log_file)
		return 0;

	log_file = fopen(log_file_path, "w");
	if (!log_file)
		return -errno;

	if (setvbuf(log_file, 0, _IOLBF, 0))
		return -errno;

	return 0;
}

void logger_set_file(FILE *file)
{
	log_file = file;
}

FILE *logger_get_file(void)
{
	return log_file;
}

int logger_clean(void)
{
	int r;

	if (!log_file)
		return 0;

	r = fclose(log_file);
	if (r == EOF)
		return -errno;

	log_file = NULL;

	return 0;
}
