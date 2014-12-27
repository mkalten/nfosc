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


#ifndef NFOSC_H
#define NFOSC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
	
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <nfc/nfc.h>
#include <nfc/nfc-types.h>
#include <lo/lo.h>
	
	pthread_t main_thread;
	
	typedef enum {
		MIFARE_ULTRALIGHT,
		MIFARE_CLASSIC_1K,
		MIFARE_CLASSIC_4K,
		MIFARE_MINI,
		MIFARE_OTHER,
	} rfid_t;
	
	typedef struct {
		int32_t device_id;
		int32_t session_id;
		int32_t symbol_id;
		int32_t type_id;
		char uid_str[32];
        bool active;
	} nfosc_t;

	void nfosc_start();
	void nfosc_stop();
	bool nfosc_check();
    void nfosc_reset();
	void nfosc_set_hostname_and_port(const char*, const char*);
	void nfosc_set_verbose(int);
	bool nfosc_running();

#ifdef __cplusplus
}
#endif

#endif
