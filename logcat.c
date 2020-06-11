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
        ulong end_data;
        ulong start_brk;
        ulong brk;
        ulong mmap_base;
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
        char task_name[TASK_COMM_LEN];
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
        if (!readmem(mm_struct + MEMBER_OFFSET("mm_struct", "end_data"), KVADDR, &logcat.end_data, sizeof(ulong), "end_data", RETURN_ON_ERROR))
                error(FATAL, "Read mm_struct end_data failed\n");
        if (!readmem(mm_struct + MEMBER_OFFSET("mm_struct", "start_brk"), KVADDR, &logcat.start_brk, sizeof(ulong), "start_brk", RETURN_ON_ERROR))
                error(FATAL, "Read mm_struct start_brk failed\n");
        if (!readmem(mm_struct + MEMBER_OFFSET("mm_struct", "mmap_base"), KVADDR, &logcat.mmap_base, sizeof(ulong), "mmap_base", RETURN_ON_ERROR))
                error(FATAL, "Read mm_struct mmap_base failed\n");
        if (!readmem(mm_struct + MEMBER_OFFSET("mm_struct", "brk"), KVADDR, &logcat.brk, sizeof(ulong), "brk", RETURN_ON_ERROR))
                error(FATAL, "Read mm_struct brk failed\n");

        register_extension(command_table);
}

char *log_prio = "UDVDIWEFS";

#define LOGBUF_ENTRY_OFFSET 0x8
#define LIST_LAST_ENTRY 0
#define LIST_NEXT_ENTRY 0x8
#define LIST_ELENMENT 0x10
int parse_log_entry(ulong log_entry)
{
        ulong log_elenment;
        struct LogBufferElement Log;
        char *msg;
        struct tm *tm;
        ulonglong nanos; 
	ulong rem;
        if(readmem(log_entry + LIST_ELENMENT, UVADDR, &log_elenment, sizeof(ulong), "log_elenment", QUIET)) {
                if(readmem(log_elenment, UVADDR, &Log, sizeof(struct LogBufferElement), "LogBufferElement", QUIET)) {
                        msg = malloc(Log.mMsgLen);
                        nanos = (ulonglong)Log.mRealTime.tv_nsec / (ulonglong)1000000000;
                        rem = (ulonglong)Log.mRealTime.tv_nsec % (ulonglong)1000000000;
                        time_t t = Log.mRealTime.tv_sec + nanos;
                        if(readmem((ulong)Log.mMsg, UVADDR, msg, Log.mMsgLen, "Log", QUIET)) {
                                /*[UID,PID,TID,PRIO,TAG,log]*/
                                tm = localtime(&t);
                                fprintf(fp, "[%02d-%02d %02d:%02d:%02d.%ld] %d %d %d %c %s:      %s\n",
                                        tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, rem, Log.mUid, Log.mPid, Log.mTid,
                                        *((char *)((ulong)log_prio + msg[0])), &msg[1], (char *)((ulong)msg + strlen(msg)+1));
                        }
                        free(msg);
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
        do {
                if(readmem(log_entry + LIST_NEXT_ENTRY, UVADDR, &next_entry, sizeof(ulong), "next_entry", QUIET)) {
                        if(readmem(next_entry + LIST_LAST_ENTRY, UVADDR, &last_entry, sizeof(ulong), "last_entry", QUIET)) {
                                if (last_entry != log_entry)
                                        return SEEK_ERROR;
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
        set_context(logcat.logd_task, NO_PID);
        /*
                static LogBuffer* logBuf = nullptr;
                traversal .bss region to locate logBuf address
        )*/
        for (addr = logcat.end_data; addr < logcat.start_brk; addr += sizeof(ulong))
        {
                if (readmem(addr, UVADDR, &logBuf, sizeof(ulong), "logBuf", QUIET)) {
                        if ((logBuf < logcat.brk) || logBuf > logcat.mmap_base)//logBuf value should belong mmap region,malloc by malloc_lib in libc.so
                                continue;
                        else {
                                if (!try_logBuf(logBuf)) {
                                        break;
                                }
                                else {
                                        continue;
                                }
                        }
                }
        }
        if (addr >= logcat.start_brk)
                fprintf(fp, "Find logBuf failed\n");
}

char *help_logcat[] = {
        "logcat",                        /* command name */
        NULL
};


