// SPDX-License-Identifier: GPL-2.0
/*
 * Tests for prctl(PR_GET_HIDE_SELF_EXE, ...) / prctl(PR_SET_HIDE_SELF_EXE, ...)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>

#include <sys/prctl.h>
#include <linux/prctl.h>

#ifndef PR_SET_HIDE_SELF_EXE
# define PR_SET_HIDE_SELF_EXE		65
# define PR_GET_HIDE_SELF_EXE		66
#endif

int main(void)
{
	int status;
	pid_t pid;
	int ret;

	ret = open("/proc/self/exe", O_RDONLY);
	if (ret < 0) {
		perror("open /proc/self/exe");
		exit(EXIT_FAILURE);
	}
	close(ret);

	ret = prctl(PR_GET_HIDE_SELF_EXE, 0, 0, 0, 0);
	if (ret != 0) {
		perror("prctl(PR_GET_HIDE_SELF_EXE)");
		exit(EXIT_FAILURE);
	}

	ret = prctl(PR_SET_HIDE_SELF_EXE, 1, 0, 0, 0);
	if (ret != 0) {
		perror("prctl(PR_SET_HIDE_SELF_EXE)");
		exit(EXIT_FAILURE);
	}

	/* check it doesn't fail a second time.  */
	ret = prctl(PR_SET_HIDE_SELF_EXE, 1, 0, 0, 0);
	if (ret != 0) {
		perror("prctl(PR_SET_HIDE_SELF_EXE)");
		exit(EXIT_FAILURE);
	}

	ret = prctl(PR_GET_HIDE_SELF_EXE, 0, 0, 0, 0);
	if (ret != 1) {
		perror("prctl(PR_GET_HIDE_SELF_EXE)");
		exit(EXIT_FAILURE);
	}

	ret = open("/proc/self/exe", O_RDONLY);
	if (ret >= 0 || errno != EPERM) {
		perror("open /proc/self/exe succeeded");
		exit(EXIT_FAILURE);
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(EXIT_FAILURE);
	}
	if (pid == 0) {
		/* It cannot be unset after a fork().  */
		ret = prctl(PR_SET_HIDE_SELF_EXE, 0, 0, 0, 0);
		if (ret == 0) {
			perror("prctl(PR_SET_HIDE_SELF_EXE)");
			exit(EXIT_FAILURE);
		}

		/* The getter still return the correct value.  */
		ret = prctl(PR_GET_HIDE_SELF_EXE, 0, 0, 0, 0);
		if (ret != 1) {
			perror("prctl(PR_GET_HIDE_SELF_EXE)");
			exit(EXIT_FAILURE);
		}

		/* It must be unreachable after fork().  */
		ret = open("/proc/self/exe", O_RDONLY);
		if (ret >= 0 || errno != EPERM)
			exit(EXIT_FAILURE);
		close(ret);

		/* It can be set again.  */
		ret = prctl(PR_SET_HIDE_SELF_EXE, 1, 0, 0, 0);
		if (ret != 0) {
			perror("prctl(PR_SET_HIDE_SELF_EXE)");
			exit(EXIT_FAILURE);
		}

		/* HIDE_SELF_EXE is cleared after execve.  */
		ret = system("cat /proc/self/exe > /dev/null");
		exit(ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	if (waitpid(pid, &status, 0) != pid) {
		perror("waitpid");
		exit(EXIT_FAILURE);
	}
	if (status != 0) {
		perror("child failed");
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}
