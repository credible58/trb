#include <windows.h>

#ifndef TDS_H
#define TDS_H

typedef struct _LOG_FIELD_HDR
{
    // ToDo: change this to enum ftenum type described in proto.h;
    UINT32 type;

    /* This length field shows Length of the value field, for ztString includes zero terminator */
    /* Prior to reading a data row, it will be zero i.e. zero in the TSDB */
    UINT32 length;

    UINT32 display;
    ULONGLONG bitmask;
} LOG_FIELD_HDR;

/* The following is needed to access the data in the TSDB in a trace file */
typedef struct _LOG_FIELD_HDR_BYTES
{
    char type[4];
    char length[4];
    char display[4];
    char bitmask[8];
} LOG_FIELD_HDR_BYTES;

typedef struct _LOG_FIELD
{
    LOG_FIELD_HDR ws_field_hdr;
    gboolean isEventTimestampData;
    char name[MAX_LOG_FIELD_NAME_LENGTH + 1];
    char abbrev[MAX_LOG_FIELD_NAME_LENGTH + 1];
    char strings[MAX_LOG_FIELD_NAME_LENGTH + 1];
    char blurb[MAX_LOG_FIELD_NAME_LENGTH + 1];

    /* The following is set as we process the data rows */
    /* In the same way that an EPB links a packet to an IDB
    the tsdb_index is used to link a text block to a TSDB */
    UINT32 tsdb_index;

    union {
        char ztString[MAX_LOG_VALUE_LENGTH];
        char byteArray[MAX_LOG_VALUE_LENGTH];
        char ipv4Addr[4];
        char ipv6Addr[16];
        UINT16 u16Field;
        UINT32 u32Field;
        UINT64 u64Field;
        UINT64 tsPcap;
    } value;
} LOG_FIELD;


#endif