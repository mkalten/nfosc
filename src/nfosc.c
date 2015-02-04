/**
 * nfosc - an OSC utility for libnfc
 *
 * Copyright (C) 2009-2015 Martin Kaltenbrunner <martin@tuio.org>
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

#ifdef CLI
#undef __APPLE__
#endif

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#endif

#define MAX_DEVICE_COUNT 8
#define MAX_TARGET_COUNT 32
#define MAX_DB_SIZE	1024

static bool running = false;
static char uid_str[32];
static nfosc_t tag_buffer[MAX_TARGET_COUNT];
static nfosc_t frame_buffer[MAX_TARGET_COUNT];
static nfosc_t tag_database[MAX_DB_SIZE];
static nfosc_t empty_tag;
static int32_t max_symbol_id = 0;
static int32_t session_id = -1;
static int32_t buffer_size = 0;
static char host[255];
static char port[255];
static char db_file_name[1024];
static int verbose = 1;

static int no_devices = 0;
static int device_count = 0;
static nfc_context *context;
static nfc_device* pnd[MAX_DEVICE_COUNT];
static lo_address target;

static char source_string[16];

char* decode_hex(const uint8_t* pbtData, const size_t szLen) {
    
    size_t szPos;
    sprintf(uid_str,"0x");
    for (szPos=0; szPos < szLen; szPos++) {
        sprintf(&uid_str[(szPos+1)*2],"%02x",pbtData[szPos]);
    }
    
    return uid_str;
}

void read_database() {
    
    int i;
#ifdef __APPLE__
    char app_path[1024];
    CFURLRef mainBundleURL = CFBundleCopyBundleURL( CFBundleGetMainBundle());
    CFStringRef cfStringRef = CFURLCopyFileSystemPath( mainBundleURL, kCFURLPOSIXPathStyle);
    CFStringGetCString( cfStringRef, app_path, 1024, kCFStringEncodingASCII);
    CFRelease( mainBundleURL);
    CFRelease( cfStringRef);
    sprintf(db_file_name,"%s/Contents/Resources/nfosc.db",app_path);
#else
    strcpy(db_file_name,"nfosc.db");
#endif
    
    nfosc_t db_entry;
    char line[36];
    FILE *db_file = fopen(db_file_name, "r");
    if (db_file==NULL) return;
    
    while (fgets (line, 32, db_file)) {
        db_entry.symbol_id = max_symbol_id;
        for (i=0; i<32; i++) {
            if (line[i]=='\n') {
                db_entry.uid_str[i]='\0';
                break;
            }
            db_entry.uid_str[i]=line[i];
        }
        if (verbose) printf("assigning ID %d to UID %s\n",max_symbol_id,db_entry.uid_str);
        tag_database[max_symbol_id] = db_entry;
        max_symbol_id++;
    }
    
    fclose (db_file);
}

void write_database() {
    int i;
    FILE *db_file = fopen(db_file_name, "w");
    if (db_file==NULL) return;
    
    for (i=0; i<max_symbol_id; i++) {
        fprintf(db_file,"%s\n",tag_database[i].uid_str);
    }
    
    fclose (db_file);
    
}

void main_loop(void *data) {
    
    int i,j,n;
    int32_t fseq = 0;
    //verbose = 2;
    
    // get the local IP adress for the TUIO2 source attribute
    char hostname[64];
    struct hostent *hp = NULL;
    struct in_addr *addr = NULL;
    
    gethostname(hostname, 64);
    hp = gethostbyname(hostname);
    
    if (hp==NULL) {
        sprintf(hostname, "%s.local", hostname);
        hp = gethostbyname(hostname);
    }
    
    if (hp!=NULL) {
        for (i = 0; hp->h_addr_list[i] != 0; ++i) {
            addr = (struct in_addr *)(hp->h_addr_list[i]);
        }
    } else {
        //generate a random internet address
        srand ( (unsigned int)time(NULL) );
        int32_t r = rand();
        addr = (struct in_addr*)&r;
    }
    
    while (running) {
        uint8_t tag_count = 0;
        bool updated = false;
        
        lo_bundle osc_bundle = lo_bundle_new(LO_TT_IMMEDIATE);
        
        nfc_target ant[MAX_TARGET_COUNT];
        
        // List ISO14443A targets
        if (verbose>1) printf("polling for a ISO14443A (MIFARE) tag:\n");
        nfc_modulation nm = {
            .nmt = NMT_ISO14443A,
            .nbr = NBR_106,
        };
        
        lo_timetag frame_time;
        lo_timetag_now (&frame_time);
        
        for (int dev=0;dev<no_devices;dev++) {
            
            if (pnd[dev] == NULL) continue;
            if (!running) return;
            
            lo_message frm_message = lo_message_new();
            lo_message_add_int32(frm_message, fseq);
            lo_message_add_timetag(frm_message, frame_time);
            lo_message_add_int32(frm_message, 0);                       // sensor dim
            if (device_count>1) sprintf(source_string, "NFOSC:%d",dev);
            lo_message_add_string(frm_message, source_string);          // source name
            lo_bundle_add_message(osc_bundle, "/tuio2/frm", frm_message);
            fseq++;
            
            int szTargetFound = nfc_initiator_list_passive_targets (pnd[dev], nm, ant, MAX_TARGET_COUNT);
            
            if (szTargetFound<0) {
                if (no_devices==1) printf("NFC reader disconnected ...\n");
                else printf("NFC reader #%d disconnected ...\n",dev);
                pnd[dev] = NULL;
                device_count--;
                if (device_count==0) {
                    running=false;
                    return;
                }
                continue;
            } else if (szTargetFound>0) {
                
                for (n = 0; n < szTargetFound; n++) {
                    if (!running) return;
                    
                    bool added = false;
                    nfosc_t found_tag;
                    found_tag.type_id = MIFARE_OTHER;
                    found_tag.device_id = dev;
                    decode_hex(ant[n].nti.nai.abtUid,ant[n].nti.nai.szUidLen);
                    strcpy(found_tag.uid_str,uid_str);
                    
                    if ((ant[n].nti.nai.abtAtqa[0] == 0x00) && (ant[n].nti.nai.abtAtqa[1] == 0x04) && (ant[n].nti.nai.btSak == 0x09)) {
                        if (verbose>1) printf("NXP MIFARE Mini - UID: %s\n",uid_str);
                        found_tag.type_id = MIFARE_MINI;
                    } else if ((ant[n].nti.nai.abtAtqa[0] == 0x00) && (ant[n].nti.nai.abtAtqa[1] == 0x04) && (ant[n].nti.nai.btSak == 0x08)) {
                        if (verbose>1) printf("NXP MIFARE Classic 1K - UID: %s\n",uid_str);
                        found_tag.type_id = MIFARE_CLASSIC_1K;
                    } else if ((ant[n].nti.nai.abtAtqa[0] == 0x00) && (ant[n].nti.nai.abtAtqa[1] == 0x02) && (ant[n].nti.nai.btSak == 0x18)) {
                        if (verbose>1) printf("NXP MIFARE Classic 4K - UID: %s\n",uid_str);
                        found_tag.type_id = MIFARE_CLASSIC_4K;
                    } else if ((ant[n].nti.nai.abtAtqa[0] == 0x00) && (ant[n].nti.nai.abtAtqa[1] == 0x02) && (ant[n].nti.nai.btSak == 0x38)) {
                        if (verbose>1) printf("Nokia MIFARE Classic 4K - emulated - UID: %s\n",uid_str);
                        found_tag.type_id = MIFARE_CLASSIC_4K;
                    } else if ((ant[n].nti.nai.abtAtqa[0] == 0x00) && (ant[n].nti.nai.abtAtqa[1] == 0x44) && (ant[n].nti.nai.btSak == 0x00)) {
                        if (verbose>1) printf("NXP MIFARE Ultralight - UID: %s\n",uid_str);
                        found_tag.type_id = MIFARE_ULTRALIGHT;
                    } else if ((ant[n].nti.nai.abtAtqa[0] == 0x03) && (ant[n].nti.nai.abtAtqa[1] == 0x44) && (ant[n].nti.nai.btSak == 0x20)) {
                        if (verbose>1) printf("NXP MIFARE DESFire - UID: %s\n",uid_str);
                    } else if ((ant[n].nti.nai.abtAtqa[0] == 0x03) && (ant[n].nti.nai.abtAtqa[1] == 0x04) && (ant[n].nti.nai.btSak == 0x28)) {
                        if (verbose>1) printf("NXP JCOP31 - UID: %s\n",uid_str);
                    } else if ((ant[n].nti.nai.abtAtqa[0] == 0x00) && (ant[n].nti.nai.abtAtqa[1] == 0x48) && (ant[n].nti.nai.btSak == 0x20)) {
                        /* @todo handle ATS to be able to know which one it is */
                        if (verbose>1) printf("NXP JCOP31 or JCOP41 - UID: %s\n",uid_str);
                    } else if ((ant[n].nti.nai.abtAtqa[0] == 0x00) && (ant[n].nti.nai.abtAtqa[1] == 0x04) && (ant[n].nti.nai.btSak == 0x28)) {
                        if (verbose>1) printf("NXP JCOP41 - UID: %s\n",uid_str);
                    } else if ((ant[n].nti.nai.abtAtqa[0] == 0x00) && (ant[n].nti.nai.abtAtqa[1] == 0x04) && (ant[n].nti.nai.btSak == 0x88)) {
                        if (verbose>1) printf("Infineon MIFARE Classic 1K - UID: %s\n",uid_str);
                        found_tag.type_id = MIFARE_CLASSIC_1K;
                    } else if ((ant[n].nti.nai.abtAtqa[0] == 0x00) && (ant[n].nti.nai.abtAtqa[1] == 0x02) && (ant[n].nti.nai.btSak == 0x98)) {
                        if (verbose>1) printf("Gemplus MPCOS - UID: %s\n",uid_str);
                    } else if ((ant[n].nti.nai.abtAtqa[0] == 0x0C) && (ant[n].nti.nai.abtAtqa[1] == 0x00)) {
                        /* @note not sure if Jewel can be detected using this modulation */
                        if (verbose>1) printf("Innovision R&T Jewel - UID: %s\n",uid_str);
                    } else {
                        if (verbose>1) {
                            printf("ATQA (SENS_RES): %s\n", decode_hex(ant[n].nti.nai.abtAtqa,2));
                            printf("   UID (NFCID%c): ",(ant[n].nti.nai.abtUid[0]==0x08?'3':'1')); printf("%s\n",decode_hex(ant[n].nti.nai.abtUid,ant[n].nti.nai.szUidLen));
                            printf("  SAK (SEL_RES): %s\n", decode_hex(&ant[n].nti.nai.btSak,1));
                            if (ant[n].nti.nai.szAtsLen) {
                                printf("      ATS (ATR): %s\n",decode_hex(ant[n].nti.nai.abtAts,ant[n].nti.nai.szAtsLen));
                            }
                            printf("\n");
                        }
                    }
                    
                    
                    int32_t symbol_id = max_symbol_id;
                    int32_t i;
                    for (i=0;i<max_symbol_id;i++) {
                        if (strcmp(tag_database[i].uid_str,found_tag.uid_str)==0) {
                            symbol_id = i;
                            found_tag.symbol_id = symbol_id;
                            break;
                        }
                    }
                    
                    if (symbol_id==max_symbol_id) {
                        symbol_id = max_symbol_id;
                        max_symbol_id++;
                        found_tag.symbol_id = symbol_id;
                        session_id++;
                        found_tag.session_id = session_id;
                        tag_database[symbol_id] = found_tag;
                        tag_buffer[buffer_size] = found_tag;
                        buffer_size++;
                        if (verbose) printf("assigning ID %d to UID %s\n",found_tag.symbol_id,found_tag.uid_str);
                        added = true;
                    } else {
                        int32_t b_pos = buffer_size;
                        for (i=0;i<buffer_size;i++) {
                            if ((strcmp(tag_buffer[i].uid_str,found_tag.uid_str)==0) && (tag_buffer[i].device_id==found_tag.device_id)) {
                                found_tag.session_id = tag_buffer[i].session_id;
                                b_pos=i;
                                break;
                            }
                        }
                        
                        if (b_pos==buffer_size) {
                            session_id++;
                            found_tag.session_id = session_id;
                            tag_buffer[buffer_size] = found_tag;
                            buffer_size++;
                            added=true;
                        }
                    }
                    
                    lo_message sym_message = lo_message_new();
                    lo_message_add_int32(sym_message, found_tag.session_id);
                    lo_message_add_int32(sym_message, found_tag.type_id);
                    lo_message_add_int32(sym_message, found_tag.symbol_id);
                    switch (found_tag.type_id) {
                        case MIFARE_ULTRALIGHT:
                            lo_message_add_string(sym_message, "mifare/ul");
                            break;
                        case MIFARE_CLASSIC_1K:
                            lo_message_add_string(sym_message, "mifare/1k");
                            break;
                        case MIFARE_CLASSIC_4K:
                            lo_message_add_string(sym_message, "mifare/4k");
                            break;
                        case MIFARE_MINI:
                            lo_message_add_string(sym_message, "mifare/mini");
                            break;
                        default:
                            lo_message_add_string(sym_message, "mifare/other");
                    }
                    lo_message_add_string(sym_message, found_tag.uid_str);
                    lo_bundle_add_message(osc_bundle, "/tuio2/sym", sym_message);
                    
                    if (added) {
                        
                        lo_message add_message = lo_message_new();
                        lo_message_add_int32(add_message, found_tag.device_id);
                        lo_message_add_int32(add_message, found_tag.symbol_id);
                        lo_message_add_int32(add_message, found_tag.type_id);
                        lo_message_add_string(add_message, found_tag.uid_str);
                        lo_bundle_add_message(osc_bundle, "/nfosc/add", add_message);
                        
                        updated = true;
                        if (verbose) printf("add %d %d %d %s\n",found_tag.device_id,found_tag.symbol_id,found_tag.type_id,found_tag.uid_str);
                    }
                    
                    frame_buffer[tag_count] = found_tag;
                    tag_count++;
                }
            }
            
            lo_message sid_message = lo_message_new();
            for (i=0;i<tag_count;i++)
                if (frame_buffer[i].device_id==dev) lo_message_add_int32(sid_message, frame_buffer[i].session_id);
            lo_bundle_add_message(osc_bundle, "/tuio2/alv", sid_message);
        }
        
        
        
        for (i=0;i<buffer_size;i++) {
            bool removed = true;
            for (j=0;j<=tag_count;j++) {
                if ((strcmp(tag_buffer[i].uid_str,frame_buffer[j].uid_str)==0) && (tag_buffer[i].device_id == frame_buffer[j].device_id))  {
                    removed=false;
                    break;
                }
            }
            if (removed) {
                
                lo_message del_message = lo_message_new();
                lo_message_add_int32(del_message, tag_buffer[i].device_id);
                lo_message_add_int32(del_message, tag_buffer[i].symbol_id);
                lo_message_add_int32(del_message, tag_buffer[i].type_id);
                lo_message_add_string(del_message, tag_buffer[i].uid_str);
                lo_bundle_add_message(osc_bundle, "/nfosc/del", del_message);
                
                updated = true;
                if (verbose) printf("del %d %d %d %s\n",tag_buffer[i].device_id,tag_buffer[i].symbol_id,tag_buffer[i].type_id,tag_buffer[i].uid_str);
            }
            
        }
        
        if (updated) {
            if(lo_send_bundle(target, osc_bundle) == -1) {
                fprintf(stderr, "an OSC error occured: %s\n", lo_address_errstr(target));
            }
        }
        
        if (verbose>1) {
            if (tag_count==0) printf("no tag was found ...\n\n");
            else if (tag_count==1) printf("1 tag was found ...\n\n");
            else printf("%d tags were found ...\n\n",tag_count);
        }
        
        buffer_size = tag_count;
        for (i=0; i<tag_count; i++) {
            tag_buffer[i] = frame_buffer[i];
            frame_buffer[i] = empty_tag;
        }
        
        for (int dev=0;dev<no_devices;dev++) {
            if (pnd[dev] == NULL) continue;
            if (nfc_device_set_property_bool(pnd[dev],NP_ACTIVATE_FIELD,false)<0) {
                if (running) {
                    if (no_devices==1) printf("NFC reader disconnected ...\n");
                    else printf("NFC reader #%d disconnected ...\n",dev);
                }
                pnd[dev] = NULL;
                device_count--;
                if (device_count==0) {
                    running=false;
                    return;
                }
            } else {
                nfc_device_set_property_bool(pnd[dev],NP_ACTIVATE_FIELD,true);
            }
        }
        usleep(1000/no_devices);
    }
}

void nfosc_stop() {
    int i;
    if (!running) return;
    running = false;
    if( main_thread ) pthread_detach(main_thread);
    main_thread = NULL;
    
    lo_bundle osc_bundle = lo_bundle_new(LO_TT_IMMEDIATE);
    for (i=0;i<buffer_size;i++) {
        
        lo_message del_message = lo_message_new();
        lo_message_add_int32(del_message, tag_buffer[i].device_id);
        lo_message_add_int32(del_message, tag_buffer[i].symbol_id);
        lo_message_add_int32(del_message, tag_buffer[i].type_id);
        lo_message_add_string(del_message, tag_buffer[i].uid_str);
        lo_bundle_add_message(osc_bundle, "/nfosc/del", del_message);
        
        if (verbose) printf("del %d %d %d %s\n",tag_buffer[i].session_id,tag_buffer[i].symbol_id,tag_buffer[i].type_id,tag_buffer[i].uid_str);
    }
    
    lo_timetag frame_time;
    lo_timetag_now (&frame_time);
    
    for (int dev=0;dev<no_devices;dev++) {
        if (pnd[dev]==NULL) continue;
        lo_message frm_message = lo_message_new();
        lo_message_add_int32(frm_message, -1);
        lo_message_add_timetag(frm_message, frame_time);
        lo_message_add_int32(frm_message, 0);                       // sensor dim
        if (device_count>1) sprintf(source_string, "NFOSC:%d",dev);
        lo_message_add_string(frm_message, source_string);          // source name
        lo_bundle_add_message(osc_bundle, "/tuio2/frm", frm_message);
        
        lo_message sid_message = lo_message_new();
        lo_bundle_add_message(osc_bundle, "/tuio2/alv", sid_message);
    }
    
    int ret = lo_send_bundle(target, osc_bundle);
    if(ret == -1) {
        fprintf(stderr, "an OSC error occured: %s\n", lo_address_errstr(target));
        exit(1);
    }
    
    for (int dev=0;dev<no_devices;dev++) {
        if (pnd[dev]!=NULL) {
            printf("closing NFC reader #%d: %s\n",dev,nfc_device_get_name(pnd[dev]));
            nfc_close(pnd[dev]);
        }
    }
    nfc_exit(context);
    write_database();
}

void nfosc_start() {
    if (running) return;
    
    max_symbol_id = 0;
    session_id = -1;
    buffer_size = 0;
    
    // try to open the NFC device
    printf("nfOSC v0.5 using libnfc v%s\n", nfc_version());
    printf("looking for NFC devices ...\n");
    fflush(stdout);
    
    nfc_init(&context);
    if (context == NULL) {
        fprintf(stderr, "unable to init libnfc (malloc)\n");
        exit(1);
    }
    
    nfc_connstring connstrings[MAX_DEVICE_COUNT];
    size_t szFound = nfc_list_devices (context, connstrings, MAX_DEVICE_COUNT);
    
    no_devices = (int)szFound;
    for (int dev=0;dev<no_devices;dev++) {
        pnd[device_count] = nfc_open(context, connstrings[dev]);
        if (pnd[device_count] == NULL) continue;
        nfc_initiator_init(pnd[device_count]);
        
        // drop the field for a while
        nfc_device_set_property_bool(pnd[device_count],NP_ACTIVATE_FIELD,false);
        
        // let the reader only try once to find a tag
        nfc_device_set_property_bool(pnd[device_count],NP_INFINITE_SELECT,false);
        
        // configure the CRC and Parity settings
        nfc_device_set_property_bool(pnd[device_count],NP_HANDLE_CRC,true);
        nfc_device_set_property_bool(pnd[device_count],NP_HANDLE_PARITY,true);
        
        // enable field so more power consuming cards can power themselves up
        nfc_device_set_property_bool(pnd[device_count],NP_ACTIVATE_FIELD,true);
        
        printf("connected to NFC reader #%d: %s\n",device_count,nfc_device_get_name(pnd[device_count]));
        device_count++;
    }
    
    no_devices = device_count;
    
    
    if (device_count==0) {
        printf("no device found!\n");
        return;
    } else if (device_count==1) {
        printf("1 device found\n");
        sprintf(source_string, "NFOSC");
    } else printf("%d devices found\n", device_count);
    
    read_database();
    
    printf("sending OSC packets to %s %s\n",host,port);
    target = lo_address_new(host, port);
    
    running = true;
    
    pthread_create(&main_thread , NULL, (void *)&main_loop, NULL);
    
}

bool nfosc_check() {
    
    nfc_context *test_context;
    nfc_connstring test_strings[MAX_DEVICE_COUNT];
    
    nfc_init(&test_context);
    if (test_context == NULL) return false;
    size_t szFound = nfc_list_devices (test_context, test_strings, MAX_DEVICE_COUNT);
    nfc_exit(context);
    if (szFound) return true;
    else return false;
}

void nfosc_reset() {
    max_symbol_id = 0;
}

void nfosc_set_verbose(int v) {
    verbose = v;
}

bool nfosc_running() {
    return running;
}

void nfosc_set_hostname_and_port(const char* h, const char* p) {
    strcpy(host,h);
    strcpy(port,p);
}
