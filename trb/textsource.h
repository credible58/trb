#ifdef __cplusplus
#include <string>
#else
#include <string.h>
#endif

#include <windows.h>

#ifndef TEXTSOURCE_H
#define TEXTSOURCE_H

/* Global limits */
#define MAX_LOG_FIELD_NAME_LENGTH 128
#define MAX_LOG_VALUE_LENGTH 4096
#define MAX_LOG_FIELD_COUNT  128
#define MAX_LOG_FIELD_FORMATS 128

#define MAX_BLOCK_DATA_LENGTH 64 * 1024

#define MAX_HF_COUNT 1024
#define MAX_TSDB_BLOCKS 256

/* Text Source support uses two blocks; Text Source Descriptor Block and Text Record Block */
#define BLOCK_TYPE_TSDB           0x80000010
#define BLOCK_TYPE_TRB            0x80000011

/* we use the TSDB version value in the TSDB subheader */
#define TSD_VERSION			   3

// These definitions are for the BABEL_HDR dataFormat
// You can add to the list but don't change any existing values
// as that will mean that Babel-converted files won't be backward
// compatible.
// 
#define RECORD_DATA_TLV_FIXED      1  // Type|Length|Value - Type|Length|Value ... Key as per the Col Header record
#define RECORD_DATA_KV_PAIR        2  // Key=Value;
#define RECORD_DATA_KTLV           3  // Key|Type|Length|Value

#define TS_FT_NONE	                0   /* used for text labels with no value */

#define EVENT_DATETIME           1001
#define TS_FT_IPvx               1002  /* Special Case */

#define TS_FT_PROTOCOL            2001
#define TS_FT_BOOLEAN             2002	/* TRUE and FALSE come from <glib.h> */
#define TS_FT_UINT8               2003
#define TS_FT_UINT16              2004
#define TS_FT_UINT24              2005	/* really a UINT32 but displayed as 6 hex-digits if FD_HEX*/
#define TS_FT_UINT32              2006
#define TS_FT_UINT40              2007	/* really a UINT64 but displayed as 10 hex-digits if FD_HEX*/
#define TS_FT_UINT48              2008	/* really a UINT64 but displayed as 12 hex-digits if FD_HEX*/
#define TS_FT_UINT56              2009	/* really a UINT64 but displayed as 14 hex-digits if FD_HEX*/
#define TS_FT_UINT64              2010
#define TS_FT_INT8                2011
#define TS_FT_INT16               2012
#define TS_FT_INT24               2013	/* same as for UINT24 */
#define TS_FT_INT32               2014
#define TS_FT_INT40               2015   /* same as for UINT40 */
#define TS_FT_INT48               2016   /* same as for UINT48 */
#define TS_FT_INT56               2017   /* same as for UINT56 */
#define TS_FT_INT64               2018
#define TS_FT_IEEE_11073_SFLOAT   2019
#define TS_FT_IEEE_11073_FLOAT    2020
#define TS_FT_FLOAT               2021
#define TS_FT_DOUBLE              2022
#define TS_FT_ABSOLUTE_TIME       2024
#define TS_FT_RELATIVE_TIME       2025
#define TS_FT_STRING              2026
#define TS_FT_STRINGZ             2027	/* for use with proto_tree_add_item() */
#define TS_FT_UINT_STRING         2028	/* for use with proto_tree_add_item() */
#define TS_FT_ETHER               2029
#define TS_FT_BYTES               2030
#define TS_FT_UINT_BYTES          2031
#define TS_FT_IPv4                2032
#define TS_FT_IPv6                2033
#define TS_FT_IPXNET              2034
#define TS_FT_FRAMENUM            2035	/* a UINT32 but if selected lets you go to frame with that number */
#define TS_FT_PCRE                2036	/* a compiled Perl-Compatible Regular Expression object */
#define TS_FT_GUID                2037	/* GUID UUID */
#define TS_FT_OID                 2038		/* OBJECT IDENTIFIER */
#define TS_FT_EUI64               2039
#define TS_FT_AX25                2040
#define TS_FT_VINES               2041
#define TS_FT_REL_OID             2042	/* RELATIVE-OID */
#define TS_FT_SYSTEM_ID           2043
#define TS_FT_STRINGZPAD          2044	/* for use with proto_tree_add_item() */
#define TS_FT_FCWWN               2045
#define TS_FT_NUM_TYPES           2046   /* last item number plus one */

#define TS_BASE_NONE          0   /**< none */
#define TS_BASE_DEC        1001   /**< decimal */
#define TS_BASE_HEX        1002   /**< hexadecimal */
#define TS_BASE_OCT        1003   /**< octal */
#define TS_BASE_DEC_HEX    1004   /**< decimal (hexadecimal) */
#define TS_BASE_HEX_DEC    1005   /**< hexadecimal (decimal) */
#define TS_BASE_CUSTOM     1006   /**< call custom routine (in ->strings) to format */


typedef struct _TSDB_SUB_HDR
{
	UINT16 version; /* Prior to BDS2 was used for type, now used for TSDB version e.g. 3 */
	UINT16 format;  /* TLV, etc. */
	UINT16 scheme_index;  /* Allows definition of multile schemes - these are then linked to the TRBs by scheme_index */
	UINT16 reserved;
	/* Adding space for future GUID support e.g. a data descriptor scheme could have a GUID */
	UINT32 guid1;
	UINT32 guid2;
	UINT32 guid3;
	UINT32 guid4;
} TSDB_SUB_HDR;

// Text Source Descriptor Block (TSDB)
typedef struct _NG_TSDB {
	UINT32 block_type;
	UINT32 block_total_length;
	TSDB_SUB_HDR tsdb_sub_hdr;
    char   schema[MAX_LOG_VALUE_LENGTH * MAX_LOG_FIELD_COUNT];
} NG_TSDB;

/* TR_HDR is the Text Record header that is carried in the TRB */
typedef struct _TR_HDR
{
    UINT32 scheme_id;
    UINT32 timestamp_high;
    UINT32 timestamp_low;
    UINT16 version; /* Version e.g. 3 */
    UINT16 format;  /* TLV, etc. */
    UINT32 reserved;
} TR_HDR;

// Text Record Block (TRB)
typedef struct _NG_TRB {
    UINT32 block_type;
    UINT32 block_total_length;
    TR_HDR tr_hdr;
    char   trb_data[MAX_BLOCK_DATA_LENGTH];
} NG_TRB;

#endif