/* logcat.c - parse android logcat from ramdump of a crash extension
 *
 * Copyright (C) 2020 xiaomi, Inc zhaoqianli.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "defs.h"      /* From the crash source top-level directory */

void logcat_init(void);    /* constructor function */
void logcat_fini(void);    /* destructor function (optional) */

void cmd_logcat(void);     /* Declare the commands and their help data. */

#define PRINT_DEBUGLOG(level, ...) \
	if (CRASHDEBUG(level))  \
	        fprintf(fp, __VA_ARGS__);

char *log_prio = "UDVDIWEFS";
#define USER_ADDR_MASK (logcat.user_addr_mask)  //android-r userspace address top 8bit tagged for dynamically detect TBI-compatible devices,prepare for ARM MTE
#define LOGBUF_ENTRY_OFFSET (logcat.logbuf_entry_offset)
#define LIST_LAST_ENTRY 0
#define LIST_NEXT_ENTRY 0x8
#define LIST_ELENMENT   0x10
#define VM_READ	        0x00000001
#define VM_WRITE        0x00000002

typedef enum log_id {
  LOG_ID_MIN = 0,

  /** The main log buffer. This is the only log buffer available to apps. */
  LOG_ID_MAIN = 0,
  /** The radio log buffer. */
  LOG_ID_RADIO = 1,
  /** The event log buffer. */
  LOG_ID_EVENTS = 2,
  /** The system log buffer. */
  LOG_ID_SYSTEM = 3,
  /** The crash log buffer. */
  LOG_ID_CRASH = 4,
  /** The statistics log buffer. */
  LOG_ID_STATS = 5,
  /** The security log buffer. */
  LOG_ID_SECURITY = 6,
  /** The kernel log buffer. */
  LOG_ID_KERNEL = 7,

  LOG_ID_MAX,

  /** Let the logging function choose the best log target. */
  LOG_ID_DEFAULT = 0x7FFFFFFF
} log_id_t;

char *help_logcat[];
struct log_time {
        uint32_t tv_sec;
        uint32_t tv_nsec;
}__attribute__ ((packed));

struct LogBufferElement{
        const uint32_t mUid;
        const uint32_t mPid;
        const uint32_t mTid;
        struct log_time mRealTime;
        char* mMsg;
        union {
        const uint16_t mMsgLen;  // mDropped == false
        uint16_t mDroppedCount;  // mDropped == true
        };
        const uint8_t mLogId;
}__attribute__ ((packed));

struct logcat_struct {
        ulong logd_task;
        ulong vma;
        ulong vm_start;
        ulong vm_end;
        ulong brk;
        ulong mmap_base;
	ulong user_addr_mask; //android-r userspace address top 8bit tagged for dynamically detect TBI-compatible devices
	ulong logbuf_entry_offset;
        log_id_t type;
};
struct logcat_struct logcat;
#define LOGD_TASK "logd"

static struct command_table_entry command_table[] = {
        { "logcat", cmd_logcat, help_logcat, 0},          /* One or more commands, */
        { NULL },                                     /* terminated by NULL, */
};


void __attribute__((constructor))
logcat_init(void) /* Register the command set. */
{
        ulong init_task, cur_task, mm_struct, task_list_offset;
        ulong file, dentry, vm_flags, end_data, start_brk;
        uint8_t find_vma = 0;
        char task_name[TASK_COMM_LEN];
        char filename[TASK_COMM_LEN] = {0};
        cur_task = init_task = symbol_value("init_task");
        task_list_offset = MEMBER_OFFSET("task_struct", "tasks");
        do {
                if (!readmem(cur_task + OFFSET(task_struct_comm), KVADDR, task_name, TASK_COMM_LEN, "task comm", RETURN_ON_ERROR))
                        error(FATAL, "Read task comm failed\n");
                if (!strcmp(task_name, LOGD_TASK))
                        break;
                if (!readmem(cur_task + task_list_offset, KVADDR, &cur_task, sizeof(ulong), "next task", RETURN_ON_ERROR))
                        error(FATAL, "Get next task failed\n");
                cur_task -= task_list_offset;
        }while (cur_task != init_task);

        if (cur_task == init_task)
                error(FATAL, "Can't find logd process\n");
        logcat.logd_task = cur_task;
        if (!readmem(cur_task + MEMBER_OFFSET("task_struct", "mm"), KVADDR, &mm_struct, sizeof(ulong), "mm_struct", RETURN_ON_ERROR))
                error(FATAL, "Get next task failed\n");
        if (!readmem(mm_struct + MEMBER_OFFSET("mm_struct", "end_data"), KVADDR, &end_data, sizeof(ulong), "end_data", RETURN_ON_ERROR))
                error(FATAL, "Read mm_struct end_data failed\n");
        if (!readmem(mm_struct + MEMBER_OFFSET("mm_struct", "start_brk"), KVADDR, &start_brk, sizeof(ulong), "start_brk", RETURN_ON_ERROR))
                error(FATAL, "Read mm_struct start_brk failed\n");
        if (!readmem(mm_struct + MEMBER_OFFSET("mm_struct", "mmap_base"), KVADDR, &logcat.mmap_base, sizeof(ulong), "mmap_base", RETURN_ON_ERROR))
                error(FATAL, "Read mm_struct mmap_base failed\n");
        if (!readmem(mm_struct + MEMBER_OFFSET("mm_struct", "brk"), KVADDR, &logcat.brk, sizeof(ulong), "brk", RETURN_ON_ERROR))
                error(FATAL, "Read mm_struct brk failed\n");
        if (!readmem(mm_struct + MEMBER_OFFSET("mm_struct", "mmap"), KVADDR, &logcat.vma, sizeof(ulong), "mmap", RETURN_ON_ERROR))
                error(FATAL, "Read mm_struct mmap failed\n");

	while (logcat.vma) {
            if (!readmem(logcat.vma + MEMBER_OFFSET("vm_area_struct", "vm_flags"), KVADDR, &vm_flags, sizeof(ulong), "vm_flags", RETURN_ON_ERROR))
                    error(FATAL, "Read vm_area_struct vm_flags failed\n");
            if ((vm_flags & VM_READ) && (vm_flags & VM_WRITE)) {  //data&bss must rw property
                if (!readmem(logcat.vma + MEMBER_OFFSET("vm_area_struct", "vm_start"), KVADDR, &logcat.vm_start, sizeof(ulong), "vm_start", RETURN_ON_ERROR))
                    error(FATAL, "Read vm_area_struct vm_start  failed\n");
                if (!readmem(logcat.vma + MEMBER_OFFSET("vm_area_struct", "vm_end"), KVADDR, &logcat.vm_end, sizeof(ulong), "vm_end", RETURN_ON_ERROR))
                    error(FATAL, "Read vm_area_struct vm_end failed\n");
                if(logcat.vm_end > end_data && logcat.vm_end <= start_brk) {  //bss must between data and heap,bss maybe a signal vma,maybe merge with data segment.
                    find_vma = 1;
                    break;
                }
            }
            //avoid deadloop
            if (!readmem(logcat.vma + MEMBER_OFFSET("vm_area_struct", "vm_file"), KVADDR, &file, sizeof(ulong), "vm_file", RETURN_ON_ERROR))
                error(FATAL, "Read mm_struct mmap failed\n");
            if (file != 0) {
                if (!readmem(file + MEMBER_OFFSET("file", "f_path") + MEMBER_OFFSET("path", "dentry"), KVADDR, &dentry, sizeof(ulong), "dentry", RETURN_ON_ERROR))
                    error(FATAL, "Read dentry failed\n");
                if (!readmem(dentry + MEMBER_OFFSET("dentry", "d_iname"), KVADDR, filename, TASK_COMM_LEN, "filename", RETURN_ON_ERROR))
                    error(FATAL, "Read dentry d_iname failed\n");
                if (strncmp(filename, LOGD_TASK, TASK_COMM_LEN))
                    break;
            }
            if (!readmem(logcat.vma + MEMBER_OFFSET("vm_area_struct", "vm_next"), KVADDR, &logcat.vma, sizeof(ulong), "vm_next", RETURN_ON_ERROR))
                    error(FATAL, "Read vm_area_struct vm_next failed\n");
        }
        if(!find_vma)
            error(FATAL, "Find data/bss section vma failed\n");
        logcat.user_addr_mask = (~((ulong)0xff<<56));
        logcat.logbuf_entry_offset = 0;
        register_extension(command_table);
}

int parse_log_entry(ulong log_entry)
{
        ulong log_elenment;
        struct LogBufferElement Log;
        char *msg;
        struct tm *tm;
        ulonglong nanos; 
	ulong rem;
        if(readmem(log_entry + LIST_ELENMENT, UVADDR, &log_elenment, sizeof(ulong), "log_elenment", QUIET)) {
		log_elenment &= USER_ADDR_MASK;
                if(readmem(log_elenment, UVADDR, &Log, sizeof(struct LogBufferElement), "LogBufferElement", QUIET)) {
                        if (logcat.type != Log.mLogId && logcat.type != LOG_ID_DEFAULT)
                          return 0;
                        msg = GETBUF(Log.mMsgLen);
                        nanos = (ulonglong)Log.mRealTime.tv_nsec / (ulonglong)1000000000;
                        rem = (ulonglong)Log.mRealTime.tv_nsec % (ulonglong)1000000000;
                        time_t t = Log.mRealTime.tv_sec + nanos;
                        if(readmem((ulong)Log.mMsg & USER_ADDR_MASK, UVADDR, msg, Log.mMsgLen, "Log", QUIET)) {
                                /*[UID,PID,TID,PRIO,TAG,log]*/
                                tm = localtime(&t);
                                fprintf(fp, "[%02d-%02d %02d:%02d:%02d.%ld] %d %d %d %c %s:      %s\n",
                                        tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, rem, Log.mUid, Log.mPid, Log.mTid,
                                        *((char *)((ulong)log_prio + msg[0])), &msg[1], (char *)((ulong)msg + strlen(msg)+1));
                        }
                        FREEBUF(msg);
                } else {
                        return READ_ERROR;
                }
        } else {
                return READ_ERROR;
        }
        return 0;
}
/* 
 *  This function is called if the shared object is unloaded. 
 *  If desired, perform any cleanups here. 
 */

int try_logBuf(ulong logBuf)
{
        ulong log_entry, last_entry, next_entry;
        log_entry = logBuf + LOGBUF_ENTRY_OFFSET;
        PRINT_DEBUGLOG(INFO, "try_logBuf logBuf:0x%lx, log_entry:0x%lx\n", logBuf, log_entry);
        do {
                if(readmem(log_entry + LIST_NEXT_ENTRY, UVADDR, &next_entry, sizeof(ulong), "next_entry", QUIET)) {
			next_entry &= USER_ADDR_MASK;
	                PRINT_DEBUGLOG(INFO, "next_entry:%lx\n", next_entry);

                        if(readmem(next_entry + LIST_LAST_ENTRY, UVADDR, &last_entry, sizeof(ulong), "last_entry", QUIET)) {
				last_entry &= USER_ADDR_MASK;
				PRINT_DEBUGLOG(INFO, "last_entry:%lx\n", last_entry);
                                if (last_entry != log_entry) {
					PRINT_DEBUGLOG(INFO, "last_entry:%lx,log_entry=%lx\n", last_entry, log_entry);
                                        return SEEK_ERROR;
				}
                                if(log_entry != (logBuf + LOGBUF_ENTRY_OFFSET)) {//skip list head
                                        parse_log_entry(log_entry);
                                }
                        }
                } else
                        return READ_ERROR;
                log_entry = next_entry;
        } while (log_entry != (logBuf + LOGBUF_ENTRY_OFFSET));

        return 0;
}

/* 
 *  Arguments are passed to the command functions in the global args[argcnt]
 *  array.  See getopt(3) for info on dash arguments.  Check out defs.h and
 *  other crash commands for usage of the myriad of utility routines available
 *  to accomplish what your task.
 */
void
cmd_logcat(void)
{
        ulong logBuf, addr;
	int c;
        set_context(logcat.logd_task, NO_PID);
        logcat.type = LOG_ID_DEFAULT;
	while ((c = getopt(argcnt, args, "Qsmrk")) != EOF) {
		switch (c) {
			case 'Q':
		                PRINT_DEBUGLOG(INFO, "android-Q logcat\n");
				logcat.user_addr_mask = (~(ulong)0x0);
				logcat.logbuf_entry_offset = 8;
				break;
                        case 's':
                                logcat.type = LOG_ID_SYSTEM;
                                break;
                        case 'm':
                                logcat.type = LOG_ID_MAIN;
                                break;
                        case 'r':
                                logcat.type = LOG_ID_RADIO;
                                break;
                        case 'k':
                                logcat.type = LOG_ID_KERNEL;
                                break;
			default:
		                PRINT_DEBUGLOG(INFO, "android-R logcat\n");
				break;
		}
	}
        /*
                static LogBuffer* logBuf = nullptr;
                traversal .bss region to locate logBuf address
        )*/
        for (addr = logcat.vm_start; addr < logcat.vm_end; addr += sizeof(ulong))
        {
                if (readmem(addr, UVADDR, &logBuf, sizeof(ulong), "logBuf", QUIET)) {
			logBuf &= USER_ADDR_MASK;
                        if ((logBuf < logcat.brk) || logBuf > logcat.mmap_base)//logBuf value should belong mmap region,malloc by malloc_lib in libc.so
                                continue;
                        else {
		                PRINT_DEBUGLOG(INFO, "cmd_logcat addr:%lx\n", addr);
                                if (!(c = try_logBuf(logBuf))) {
                                        break;
                                }
                                else {
					PRINT_DEBUGLOG(INFO, "try_logBuf ret=%d\n", c);
                                        continue;
                                }
                        }
                }
        }
        if (addr >= logcat.vm_end)
                fprintf(fp, "Find logBuf failed\n");
}

char *help_logcat[] = {
        "logcat",                        /* command name */
        "parse android logcat from ramdump of a crash extension\n",
        "parse android main logcat",
        "command support Android-R default,use \"logcat -Q\" to support older version",
        "use \"logcat -s/-m/-r/-k\" to support system/main/radio/kernel log,default show all logs",
        "Any question please contact zhaoqianli@xiaomi.com",
        "version V3",
        NULL
};
