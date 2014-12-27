/**
 * nfosc - an OSC utility for libnfc
 *
 * Copyright (C) 2009-14, Martin Kaltenbrunner <martin@tuio.org>
 * 
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>
 */

#include "nfosc.h"

#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

static bool running = false;
static bool verbose = false;
static bool tuio = false;
static char *host = "localhost";
static char *port = "3333";

static void show_help()
{
	printf("Usage: nfosc [options] [host] [port]\n");
	printf("        -v verbose\n");
	printf("        -h show help\n");
}

static void stop(int param)
{
	running = false;
	printf(" break ...\n");
}

static void init(int argc, char** argv)
{
	int aflag = 0;
	int bflag = 0;
	char *cvalue = NULL;
	int index;
	int c;

	opterr = 0;

	while ((c = getopt(argc, argv, "vth")) != -1) {
		switch (c) {
			case 'v':
				verbose = true;
				break;
			case 'h':
				show_help();
				exit(0);
			default:
				show_help();
				exit(1);
		}
	}

	for (index=optind, c=0; index < argc; index++, c++) {
		switch (c) {
			case 0:
				host = argv[index];
				break;
			case 1:
				port = argv[index];
				break;
			default:
				break;
		}
	}
}

int main(int argc, char** argv)
{
	init(argc, argv);

	signal(SIGINT, stop);
	signal(SIGHUP, stop);
	signal(SIGQUIT, stop);
	signal(SIGTERM, stop);

	nfosc_set_hostname_and_port(host, port);
	nfosc_set_verbose(verbose);
	nfosc_start();

if (nfosc_running()) {
	printf("Press Ctrl+C to end this program.\n");
	running = true;
}
	// Loop until the program is stopped.
	while (running) { 
		usleep(1000);
		if (!nfosc_running()) running = false;
	};

	nfosc_stop();
	return 0;
}


