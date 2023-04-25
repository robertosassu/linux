// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the UMD handler.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#include "pgp/pgplib.h"

int alg_fds_array[FD__LAST] = { -1 };
const char *alg_strs[] = { "sha1", "md5", NULL };

static int get_alg_fd(const char *alg_name)
{
	struct sockaddr_alg sa = {
		.salg_family = 38,
		.salg_type = "hash",
	};

	int ret, fd, fd_accept = -1;

	strlcpy((char *)sa.salg_name, alg_name, sizeof(sa.salg_name));

	fd = socket(38, SOCK_SEQPACKET, 0);
	if (fd == -1)
		return fd;

	ret = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (ret == -1)
		goto out;

	fd_accept = accept(fd, NULL, 0);
out:
	close(fd);
	return fd_accept;
}

static void close_alg_fds(void)
{
	int i;

	for (i = 0; i < FD__LAST; i++)
		if (alg_fds_array[i] >= 0)
			close(alg_fds_array[i]);
}

FILE *debug_f;

int main(int argc, char *argv[])
{
	struct msg_in *in = NULL;
	struct msg_out *out = NULL;
	size_t in_len, out_len;
	loff_t pos;
	int ret = 0, i;

	for (i = 0; i < FD__LAST; i++) {
		alg_fds_array[i] = get_alg_fd(alg_strs[i]);
		if (alg_fds_array[i] == -1) {
			close_alg_fds();
			exit(1);
		}
	}
#ifdef debug
	debug_f = fopen("/dev/kmsg", "a");
	fprintf(debug_f, "<5>Started %s\n", argv[0]);
	fflush(debug_f);
#endif
	in = malloc(sizeof(*in));
	if (!in)
		goto out;

	out = malloc(sizeof(*out));
	if (!out)
		goto out;

	while (1) {
		int n;

		in_len = sizeof(*in);
		out_len = sizeof(*out);

		memset(in, 0, in_len);
		memset(out, 0, out_len);

		pos = 0;
		while (in_len) {
			n = read(0, (void *)in + pos, in_len);
			if (n <= 0) {
				ret = -EIO;
				goto out;
			}
			in_len -= n;
			pos += n;
		}

		switch (in->cmd) {
		case CMD_KEY:
			pgp_key_parse_umh(in, out);
			break;
		case CMD_SIG:
			pgp_sig_parse_umh(in, out);
			break;
		default:
			out->ret = -EOPNOTSUPP;
			break;
		}

		pos = 0;
		while (out_len) {
			n = write(1, (void *)out + pos, out_len);
			if (n <= 0) {
				ret = -EIO;
				goto out;
			}
			out_len -= n;
			pos += n;
		}
	}
out:
	close_alg_fds();
	free(in);
	free(out);
#ifdef debug
	fclose(debug_f);
#endif
	return ret;
}
