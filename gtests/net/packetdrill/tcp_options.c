/*
 * Copyright 2013 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
/*
 * Author: ncardwell@google.com (Neal Cardwell)
 *
 * Implementation for reading and writing TCP options in their wire format.
 */

#include "tcp_options.h"

#include <stdlib.h>
#include <string.h>
#include "packet.h"

struct tcp_options *tcp_options_new(void)
{
	struct tcp_options *options = calloc(1, sizeof(struct tcp_options));

	if (!options)
		return NULL;

	options->data = calloc(1, sizeof(u8) * MAX_TCP_OPTION_BYTES);
	if (!options->data) {
		free(options);
		return NULL;
	}

	options->max = MAX_TCP_OPTION_BYTES;

	return options;
}

struct tcp_option *tcp_option_new(u8 kind, u8 length)
{
	struct tcp_option *option = calloc(1, sizeof(struct tcp_option));
	option->kind = kind;
	option->length = length;
	return option;
}

int tcp_options_append(struct tcp_options *options, struct tcp_option *option,
		       char **error)
{
	int total_length = options->length + option->length;

	if (total_length > options->max) {
		u8 *old_data = options->data;

		if (!options->edo ||
		    total_length > UINT16_MAX - sizeof(struct tcphdr)) {
			asprintf(error, "TCP option list too long");
			return STATUS_ERR;
		}

		options->max *= 2;
		if (options->max > UINT16_MAX)
			options->max = UINT16_MAX;

		options->data = calloc(1, options->max);
		if (!options->data) {
			asprintf(error, "Out of memory for TCP option list");
			return STATUS_ERR;
		}

		options->edo = offset_ptr(old_data, options->data, options->edo);
		memcpy(options->data, old_data, options->length);
		free(old_data);
	}

	if (tcp_option_is_edo(option) &&
	    option->length >= TCPOLEN_EXP_EDO_EXT_HDR) {
		if (option->length != TCPOLEN_EXP_EDO_EXT_HDR &&
		    option->length != TCPOLEN_EXP_EDO_EXT_SEG) {
			asprintf(error, "TCP EDO invalid length");
			return STATUS_ERR;
		}

		if (options->edo) {
			asprintf(error, "TCP EDO set twice");
			return STATUS_ERR;
		}

		/* 2 is of Kind and Length, struct edo does not have them. */
		options->edo = (struct edo *)(options->data + options->length + 2);
		options->auto_hdr = option->data.edo.auto_hdr;
		options->auto_seg = option->data.edo.auto_seg;
	}

	memcpy(options->data + options->length, option, option->length);
	options->length = total_length;
	assert(options->length <= options->max);
	free(option);
	return STATUS_OK;
}

bool tcp_option_is_edo(struct tcp_option *option)
{
	if (option->kind != TCPOPT_EXP)
		return false;

	if (option->length < TCPOLEN_EXP_EDO_SUP)
		return false;

	return ntohs(option->data.edo.magic) == TCPOPT_EDO_MAGIC;
}

int num_sack_blocks(u8 opt_len, int *num_blocks, char **error)
{
	if (opt_len <= 2) {
		asprintf(error, "TCP SACK option too short");
		return STATUS_ERR;
	}
	const int num_bytes = opt_len - 2;
	if (num_bytes % sizeof(struct sack_block) != 0) {
		asprintf(error,
			 "TCP SACK option not a multiple of SACK block size");
		return STATUS_ERR;
	}
	*num_blocks = num_bytes / sizeof(struct sack_block);
	return STATUS_OK;
}
