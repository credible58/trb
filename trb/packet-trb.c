/* packet-trb.c

   Test plugin
*/

#include "config.h"

#include <ws_symbol_export.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/plugin_if.h>
#include <wiretap/pcapng_module.h>
#include <wiretap/wtap-int.h>
#include <epan/wmem/wmem.h>

#include "textsource.h"
#include "trb.h"

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif /* HAVE_ZLIB */

void proto_register_trb(void);
void proto_reg_handoff_trb(void);

static dissector_handle_t trb_handle;

static wmem_map_t *test_map;

///////////////////////////////////

// ToDo: The following is copied from file_wrappers.c
// Need to find out if such a structure definition being placed in a .c file was intentional
// e.g. it's envisaged that there may be variants in the future and so other definitions in
// other .c files
//
// Having a copy here is not viable going forward as we will get problems of the definition here 
// getting out of step with the version in file_wrappers.c

/* values for wtap_reader compression */
typedef enum {
    UNKNOWN,       /* unknown - look for a gzip header */
    UNCOMPRESSED,  /* uncompressed - copy input directly */
#ifdef HAVE_ZLIB
    ZLIB,          /* decompress a zlib stream */
    GZIP_AFTER_HEADER
#endif
} compression_t;

/* Interface data in private struct */
typedef struct interface_info_s {
    int wtap_encap;
    guint32 snap_len;
    guint64 time_units_per_second;
    int tsprecision;
} interface_info_t;

struct wtap_reader {
    int fd;                    /* file descriptor */
    gint64 raw_pos;            /* current position in file (just to not call lseek()) */
    gint64 pos;                /* current position in uncompressed data */
    guint size;                /* buffer size */
    unsigned char *in;         /* input buffer */
    unsigned char *out;        /* output buffer (double-sized when reading) */
    unsigned char *next;       /* next output data to deliver or write */

    guint have;                /* amount of output data unused at next */
    gboolean eof;              /* TRUE if end of input file reached */
    gint64 start;              /* where the gzip data started, for rewinding */
    gint64 raw;                /* where the raw data started, for seeking */
    compression_t compression; /* type of compression, if any */
    gboolean is_compressed;    /* FALSE if completely uncompressed, TRUE otherwise */
                               /* seek request */
    gint64 skip;               /* amount to skip (already rewound if backwards) */
    gboolean seek_pending;     /* TRUE if seek request pending */
                               /* error information */
    int err;                   /* error code */
    const char *err_info;      /* additional error information string for some errors */

    guint avail_in;            /* number of bytes available at next_in */
    unsigned char *next_in;    /* next input byte */
#ifdef HAVE_ZLIB
                               /* zlib inflate stream */
    z_stream strm;             /* stream structure in-place (not a pointer) */
    gboolean dont_check_crc;   /* TRUE if we aren't supposed to check the CRC */
#endif
                               /* fast seeking */
    GPtrArray *fast_seek;
    void *fast_seek_cur;
};

#define ETHERTYPE_BABEL2 0xbab2

#define BLOCK_TYPE_SECTION_HEADER         0x0A0D0D0A
#define BLOCK_TYPE_INTERFACE_DESCRIPTOR   0x00000001
#define BLOCK_TYPE_ENHANCED_PACKET        0x00000006
#define BLOCK_TYPE_TEXT_SOURCE_DESCRIPTOR 0x00000010
#define BLOCK_TYPE_TEXT_RECORD            0x00000011
#define BLOCK_TYPE_CUSTOM                 0x00000BAD

#define MAX_SCHEMA_SIZE 16*1024


// Globals
gboolean is_proto_registered = FALSE;

interface_info_t iface_info;

ws_info_t *ws_info;

hf_register_info hf[MAX_HF_COUNT]; /* The hf array that is registered with WS */
int hf_id[MAX_HF_COUNT]; /* Once the header fields have been registered, this array contains the matching hf ids. */
int hf_count = 0; /* The count of the number of entries in the hf and hf_id arrays. */

                  /* We want to support multiple text data record formats, and so multiple schema defined in multiple TSDBs.  Wireshark
                  doesn't have a concept of multiple schema in a single dissector and so we must provide the support.  The hf and hf_id
                  arrays above have a single dimension.  We need an array that has two dimensions of scheme index (once for each TSDB)
                  and field index.  The integer entry held in this two dimensional array is an index into the hf and hf_id arrays.
                  We'll call the array hf_matrix.  A value of -1 indicates that we've reached the end of the valid entries. */
int hf_matrix[MAX_TSDB_BLOCKS][MAX_HF_COUNT];

int proto_trb = -1;

static gint ett_bds = -1;
static gint ett_trb_header = -1;
static gint ett_trb_data = -1;

LOG_FIELD field_array[MAX_LOG_FIELD_COUNT];
char info_string[256];

typedef struct _schema_field {
    enum ftenum type;
    int display;
    guint64 bitmask;
} schema_field;

static const value_string vs_format[] = {
    { RECORD_DATA_TLV_FIXED, "Type|Length|Value" },
    { RECORD_DATA_KV_PAIR, "Key=Value" },
    { RECORD_DATA_KTLV, "Key|Type|Length|Value" },
    { 0, NULL }
};

static guint32 babeltowsft[][2] = {
    { TS_FT_PROTOCOL, FT_PROTOCOL },
    { TS_FT_BOOLEAN, FT_BOOLEAN },
    { TS_FT_UINT8, FT_UINT8 },
    { TS_FT_UINT16, FT_UINT16 },
    { TS_FT_UINT24, FT_UINT24 },
    { TS_FT_UINT32, FT_UINT32 },
    { TS_FT_UINT40, FT_UINT40 },
    { TS_FT_UINT48, FT_UINT48 },
    { TS_FT_UINT56, FT_UINT56 },
    { TS_FT_UINT64, FT_UINT64 },
    { TS_FT_INT8, FT_INT8 },
    { TS_FT_INT16, FT_INT16 },
    { TS_FT_INT24, FT_INT24 },
    { TS_FT_INT32, FT_INT32 },
    { TS_FT_INT40, FT_INT40 },
    { TS_FT_INT48, FT_INT48 },
    { TS_FT_INT56, FT_INT56 },
    { TS_FT_INT64, FT_INT64 },
    { TS_FT_IEEE_11073_SFLOAT, FT_IEEE_11073_SFLOAT },
    { TS_FT_IEEE_11073_FLOAT, FT_IEEE_11073_FLOAT },
    { TS_FT_FLOAT, FT_FLOAT },
    { TS_FT_DOUBLE, FT_DOUBLE },
    { TS_FT_ABSOLUTE_TIME, FT_ABSOLUTE_TIME },
    { TS_FT_RELATIVE_TIME, FT_RELATIVE_TIME },
    { TS_FT_STRING, FT_STRING },
    { TS_FT_STRINGZ, FT_STRINGZ },
    { TS_FT_UINT_STRING, FT_UINT_STRING },
    { TS_FT_ETHER, FT_ETHER },
    { TS_FT_BYTES, FT_BYTES },
    { TS_FT_UINT_BYTES, FT_UINT_BYTES },
    { TS_FT_IPv4, FT_IPv4 },
    { TS_FT_IPv6, FT_IPv6 },
    { TS_FT_IPXNET, FT_IPXNET },
    { TS_FT_FRAMENUM, FT_FRAMENUM },
    { TS_FT_PCRE, FT_PCRE },
    { TS_FT_GUID, FT_GUID },
    { TS_FT_OID, FT_OID },
    { TS_FT_EUI64, FT_EUI64 },
    { TS_FT_AX25, FT_AX25 },
    { TS_FT_VINES, FT_VINES },
    { TS_FT_REL_OID, FT_REL_OID },
    { TS_FT_SYSTEM_ID, FT_SYSTEM_ID },
    { TS_FT_STRINGZPAD, FT_STRINGZPAD },
    { TS_FT_FCWWN, FT_FCWWN },
    { TS_FT_NUM_TYPES, FT_NUM_TYPES }
};


#define TS_BASE_NONE          0   /**< none */
#define TS_BASE_DEC        1001   /**< decimal */
#define TS_BASE_HEX        1002   /**< hexadecimal */
#define TS_BASE_OCT        1003   /**< octal */
#define TS_BASE_DEC_HEX    1004   /**< decimal (hexadecimal) */
#define TS_BASE_HEX_DEC    1005   /**< hexadecimal (decimal) */
#define TS_BASE_CUSTOM     1006   /**< call custom routine (in ->strings) to format */

static guint32 babeltowsdisplay[][2] = {
    { TS_BASE_NONE, BASE_NONE },
    { TS_BASE_DEC, BASE_DEC },
    { TS_BASE_HEX, BASE_HEX },
    { TS_BASE_OCT, BASE_OCT },
    { TS_BASE_DEC_HEX, BASE_DEC_HEX },
    { TS_BASE_HEX_DEC, BASE_HEX_DEC },
    { TS_BASE_CUSTOM, BASE_CUSTOM }
};

/* The following defaults are copied into the hf array that is registered with WS. */
static hf_register_info hf_defaults[] = {
    { NULL,
    { "TRB Version", "trb.version",
    FT_UINT16, BASE_DEC, NULL, 0x0,
    "Version of the TSDB and TRB blocks", HFILL }
    },

    { NULL,
    { "TRB Format", "trb.format",
    FT_UINT16, BASE_DEC,
    vs_format, 0x0,
    NULL, HFILL }
    },

    { NULL,
    { "Scheme Index", "trb.scheme.index",
    FT_UINT16, BASE_DEC, NULL, 0x0,
    "Record format scheme index", HFILL }
    }
};

hf_register_info *get_hf(size_t scheme_index, size_t field_index)
{
    return &hf[hf_matrix[scheme_index][field_index]];
}

int babel_to_ws_ft(guint32 babel_ft)
{
    size_t i;

    for (i = 0; i < ARRAYSIZE(babeltowsft); i++)
    {
        if (babeltowsft[i][0] == babel_ft)
            return babeltowsft[i][1];
    }
    return FT_STRINGZ;
}

int babel_to_ws_display(guint32 babel_ft)
{
    size_t i;

    for (i = 0; i < ARRAYSIZE(babeltowsdisplay); i++)
    {
        if (babeltowsdisplay[i][0] == babel_ft)
            return babeltowsdisplay[i][1];
    }
    return BASE_NONE;
}

guint64 ptouint64(char *bytes)
{
    union
    {
        guint64 value;
        char bytes_in[8];
    } map;

    memcpy(map.bytes_in, bytes, 8);

    return map.value;
}

guint32 ptouint32(char *bytes)
{
    union
    {
        guint32 value;
        char bytes_in[4];
    } map;

    memcpy(map.bytes_in, bytes, 4);

    return map.value;
}

gboolean hf_append(char *name, char *abbrev, enum ftenum type, int display, void *strings, guint64 bitmask, char *blurb)
{
    if (hf_count < MAX_HF_COUNT)
    {
        hf[hf_count].hfinfo.name = name;
        hf[hf_count].hfinfo.abbrev = abbrev;
        hf[hf_count].hfinfo.type = type;
        hf[hf_count].hfinfo.display = display;
        hf[hf_count].hfinfo.strings = strings;
        hf[hf_count].hfinfo.bitmask = bitmask;
        hf[hf_count].hfinfo.blurb = blurb;

        /* initialise the remaining fields*/
        HFILL_INIT(hf[hf_count]);

        hf_count++;

        return TRUE;
    }

    return FALSE;
}


void process_schema(char *schema_data, int length, size_t scheme_index)
{
    // on entry length is 404 bytes but should be 400 - more alignment issues?
    char *ptr = schema_data;
    gboolean dummy_boolean;
    size_t field_index = 0;

    /* when we enter here we will already have three hf array entries covering the BDS message header values */

    while (ptr - schema_data < length)
    {
        LOG_FIELD_HDR_BYTES *field_hdr_bytes = (LOG_FIELD_HDR_BYTES *)ptr;

        /* ToDo: Replace this code to use hf_append */

        hf[hf_count].hfinfo.type = babel_to_ws_ft(ptouint32(field_hdr_bytes->type));
        ptr += 4;
        hf[hf_count].hfinfo.display = babel_to_ws_display(ptouint32(field_hdr_bytes->display));
        ptr += 4;
        hf[hf_count].hfinfo.bitmask = ptouint64(field_hdr_bytes->bitmask);
        ptr += 8;

        /* skip isEventTimestampData */
        ptr += sizeof(dummy_boolean);

        hf[hf_count].hfinfo.name = g_strdup(ptr);
        ptr += strlen(ptr) + 1;

        hf[hf_count].hfinfo.abbrev = g_strdup(ptr);
        ptr += strlen(ptr) + 1;

        hf[hf_count].hfinfo.strings = NULL;
        ptr += strlen(ptr) + 1;

        hf[hf_count].hfinfo.blurb = g_strdup(ptr);
        ptr += strlen(ptr) + 1;

        /* initialise the remaining fields*/
        HFILL_INIT(hf[hf_count]);

        /* skip any padding bytes */
        while (*ptr == 0x00 && (ptr - schema_data < length))
            ptr++;

        hf_matrix[scheme_index][field_index] = hf_count;

        field_index++;
        hf_count++;
    }
}


int process_dsv_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gint tvb_offset, TR_HDR *record_hdr, size_t scheme_index)
{
    UINT16 field_type;
    UINT16 field_length;
    int field_index = 0;
    hf_register_info *p_hf;
    char *str;

    int pdu_length = tvb_captured_length(tvb);

    while (tvb_offset <= pdu_length - 8)
    {
        field_type = babel_to_ws_ft(tvb_get_letohs(tvb, tvb_offset));
        tvb_offset += 4;

        field_length = tvb_get_letohs(tvb, tvb_offset);
        tvb_offset += 4;

        p_hf = get_hf(scheme_index, field_index);

        if (!strcmp(p_hf->hfinfo.name, "cs-method"))
        {
            str = tvb_get_string_enc(wmem_packet_scope(), tvb, tvb_offset, field_length, ENC_ASCII | ENC_NA);
            strcat(info_string, str);
        }

        else if (!strcmp(p_hf->hfinfo.name, "cs-uri-stem"))
        {
            str = tvb_get_string_enc(wmem_packet_scope(), tvb, tvb_offset, field_length, ENC_ASCII | ENC_NA);
            strcat(info_string, " ");
            strcat(info_string, str);
        }

        else if (!strcmp(p_hf->hfinfo.name, "cs-uri-query"))
        {
            str = tvb_get_string_enc(wmem_packet_scope(), tvb, tvb_offset, field_length, ENC_ASCII | ENC_NA);
            if (strcmp(str, "-"))
            {
                strcat(info_string, "?");
                strcat(info_string, str);
            }
        }

        if (field_length > 0)
        {
            switch (field_type)
            {
            case FT_UINT16:
            case FT_UINT32:
            case FT_UINT64:
                proto_tree_add_item(tree, p_hf->hfinfo.id, tvb, tvb_offset, field_length, ENC_LITTLE_ENDIAN);
                break;

            case FT_IPv4:
                proto_tree_add_item(tree, p_hf->hfinfo.id, tvb, tvb_offset, field_length, ENC_NA);
                break;

            case FT_IPv6:
                proto_tree_add_item(tree, p_hf->hfinfo.id, tvb, tvb_offset, field_length, ENC_NA);
                break;

            case FT_STRINGZ:
                proto_tree_add_item(tree, p_hf->hfinfo.id, tvb, tvb_offset, field_length, ENC_ASCII | ENC_NA);
                break;

            default:
                return pdu_length - sizeof(TR_HDR);
            }
        }

        field_index++;
        tvb_offset += field_length;
    }

    return pdu_length - sizeof(TR_HDR);
}


gboolean process_TSDBs(guint8 *block_data, int tsdb_length)
{
    size_t scheme_index = 0;

    /* To get the schema length subtract the length of the tsdb_hdr from the tsdb_length */
    int scheme_length = tsdb_length - sizeof(TSDB_SUB_HDR);

    char *schema = block_data + sizeof(TSDB_SUB_HDR);

    process_schema(schema, scheme_length, scheme_index++);

    return TRUE;
}


/**
* This routine is called before we process packet 1 on the first pass
* Unfortunately, we have to leave it this late because this is the first
* time we can get the capture file name
*/
void init_trb(void)
{
    iface_info.time_units_per_second = 1000000;
    iface_info.tsprecision = 6;
}

/**
* Cleanup routine which is called
* after closing a capture file (or when preferences are changed, in
* that case these routines are called before the init routines are
* executed). It can be used to release resources that are allocated in
* register_init_routine.
*/
void clean_up(void)
{
    plugin_if_get_ws_info(&ws_info);

    if (ws_info->cf_state == FILE_CLOSED)
    {
        /* Initialise the hf_ids and the pointers to them */
        for (size_t i = 0; i < MAX_HF_COUNT; i++)
        {
            if (hf_id[i] != -1)
                proto_deregister_field(proto_trb, hf_id[i]);

            hf_id[i] = -1;
            hf[i].p_id = &hf_id[i];
        }

        proto_free_deregistered_fields();
    }

    return;
}

/*
INPUTS

OUTPUTS
wtap_pkthdr
*/
// (FILE_T, guint32, gboolean, wtapng_block_t *, int *, gchar **);
gboolean tsdb_read_block(FILE_T fh, guint32 block_data_len, gboolean c, wtapng_block_t *wtapng_block,
    int *err, gchar **err_info)
{
    /* Use i as a general purpose index */
    size_t i;

    /* Signal that this isn't a "packet" block */
    wtapng_block->internal = TRUE;

    /*
    * Is the size of this block reasonable for a TSDB?
    */
    if (block_data_len == 0 || block_data_len > wtapng_block->frame_buffer->allocated) {
        /* Not looking good. */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = wmem_strdup_printf(wmem_file_scope(), "tsdb_read_block: block data length of %u is invalid",
            block_data_len);
        return FALSE;
    }

    /* read block content */
    if (!wtap_read_bytes(fh, wtapng_block->frame_buffer->data, block_data_len, err, err_info)) {
        wmem_strdup_printf(wmem_file_scope(), "tsdb_read_block: failed to read TSDB");
        return FALSE;
    }

    if (hf_id[0] == -1)
    {
        /* We only need to do the following if the hf structures haven't been registered */
        /* Initialise the hf_matrix */
        for (i = 0; i < MAX_TSDB_BLOCKS; i++)
        {
            for (size_t j = 0; j < MAX_HF_COUNT; j++)
                hf_matrix[i][j] = -1;
        }

        /* Initialise the hf_ids and the pointers to them */
        for (i = 0; i < MAX_HF_COUNT; i++)
        {
            hf_id[i] = -1;
            hf[i].p_id = &hf_id[i];
            hf[i].hfinfo.name = NULL;
            hf[i].hfinfo.abbrev = NULL;
            hf[i].hfinfo.strings = NULL;
            hf[i].hfinfo.blurb = NULL;
        }

        /* Load the hf array with the default TSD header values */
        for (hf_count = 0; hf_count < 3; hf_count++)
        {
            hf[hf_count].p_id = &hf_id[hf_count];
            hf[hf_count].hfinfo.name = g_strdup(hf_defaults[hf_count].hfinfo.name);
            hf[hf_count].hfinfo.abbrev = g_strdup(hf_defaults[hf_count].hfinfo.abbrev);
            hf[hf_count].hfinfo.type = hf_defaults[hf_count].hfinfo.type;
            hf[hf_count].hfinfo.display = hf_defaults[hf_count].hfinfo.display;
            hf[hf_count].hfinfo.strings = NULL;
            hf[hf_count].hfinfo.bitmask = hf_defaults[hf_count].hfinfo.bitmask;
            hf[hf_count].hfinfo.blurb = g_strdup(hf_defaults[hf_count].hfinfo.blurb);
        }

        if (!process_TSDBs(wtapng_block->frame_buffer->data, block_data_len))
        {
            /* probably not a PCAP-NG file */
            return FALSE;
        }

        /* The hf array now has all the values we need to register all likely fields */
        proto_register_field_array(proto_trb, hf, hf_count);
    }

    return TRUE;
}

void tsdb_create(wtap_block_t block)
{
    return;
}

void tsdb_free_mand(wtap_block_t block)
{
    return;
}

void tsdb_copy_mand(wtap_block_t dest_block, wtap_block_t src_block)
{
    return;
}

gboolean trb_read_block(FILE_T fh, guint32 block_data_len, gboolean is_byte_swapped, wtapng_block_t *wtapng_block,
    int *err, gchar **err_info)
{
    guint64 ts;
    guint32 ts_high;
    guint32 ts_low;

    TR_HDR *tr_hdr = (TR_HDR *)wtapng_block->frame_buffer->data;

    /*
    * Is the size of this block reasonable for a TRB?
    */
    if (block_data_len == 0 || block_data_len > wtapng_block->frame_buffer->allocated) {
        /* Not looking good. */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = wmem_strdup_printf(wmem_file_scope(), "trb_read_block: block data length of %u is invalid",
            block_data_len);
        return FALSE;
    }

    /* read block content */
    if (!wtap_read_bytes(fh, wtapng_block->frame_buffer->data, block_data_len, err, err_info)) {
        wmem_strdup_printf(wmem_file_scope(), "trb_read_block: failed to read TRB");
        return FALSE;
    }

    /* Populate the wtapng_block */
    if (is_byte_swapped) {
        ts_high = GUINT32_SWAP_LE_BE(tr_hdr->timestamp_high);
        ts_low = GUINT32_SWAP_LE_BE(tr_hdr->timestamp_low);
        wtapng_block->packet_header->caplen = GUINT32_SWAP_LE_BE(block_data_len);
        wtapng_block->packet_header->len = GUINT32_SWAP_LE_BE(block_data_len);
    }
    else {
        ts_high = tr_hdr->timestamp_high;
        ts_low = tr_hdr->timestamp_low;
        wtapng_block->packet_header->caplen = block_data_len;
        wtapng_block->packet_header->len = block_data_len;
    }

    /* Combine the two 32-bit pieces of the timestamp into one 64-bit value */
    ts = (((guint64)ts_high) << 32) | ((guint64)ts_low);
    wtapng_block->packet_header->ts.secs = (time_t)(ts / iface_info.time_units_per_second);
    wtapng_block->packet_header->ts.nsecs = (int)(((ts % iface_info.time_units_per_second) * 1000000000) / iface_info.time_units_per_second);

    wtapng_block->internal = FALSE;
    wtapng_block->packet_header->interface_id = 0;
    wtapng_block->packet_header->drop_count = -1; /* invalid */
    wtapng_block->packet_header->caplen = block_data_len;
    wtapng_block->packet_header->len = block_data_len;
    wtapng_block->packet_header->pkt_encap = WTAP_ENCAP_USER11;
    wtapng_block->packet_header->presence_flags |= WTAP_HAS_TS;
    wtapng_block->packet_header->presence_flags |= WTAP_HAS_INTERFACE_ID;
    wtapng_block->packet_header->presence_flags |= WTAP_HAS_CAP_LEN;
    wtapng_block->packet_header->rec_type = REC_TYPE_PACKET;
    wtapng_block->packet_header->pkt_tsprec = 6;

    return TRUE;
}

void trb_create(wtap_block_t block)
{
    return;
}

void trb_free_mand(wtap_block_t block)
{
    return;
}

void trb_copy_mand(wtap_block_t dest_block, wtap_block_t src_block)
{
    return;
}

int get_hf_array_entry(char *field_name, guint16 field_type)
{
    int i;

    int ws_field_type = 0;
    if (field_type == TS_FT_IPv4) ws_field_type = FT_IPv4;
    if (field_type == TS_FT_IPv6) ws_field_type = FT_IPv6;


    for (i = 0; i < hf_count; i++)
    {
        if (!strcmp(hf[i].hfinfo.name, field_name))
        {
            // The following is needed as we can have IPv4 and IPv6 addresses in the same column i.e. with the same name
            if (ws_field_type > 0) // if this is an IP address check the type
            {
                if (hf[i].hfinfo.type == ws_field_type)
                    return hf_id[i];
            }
            else
                break;
        }
    }

    /* If we haven't found a match, return the pid for the unknown string */
    return hf_id[2];
}

static int dissect_trb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree *tr_tree;
    proto_tree *tr_header_tree;
    proto_tree *tr_body_tree;
    proto_item *ti;
    TR_HDR tr_hdr;
    gint tvb_offset = 0;
    info_string[0] = '\0';

    // Not interested in first scan
    if (!PINFO_FD_VISITED(pinfo))
        return tvb_captured_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TRB");

    ti = proto_tree_add_item(tree, proto_trb, tvb, 0, -1, ENC_NA);
    tr_tree = proto_item_add_subtree(ti, ett_bds);
    tr_header_tree = proto_tree_add_subtree(tr_tree, tvb, tvb_offset, 16, ett_trb_header, NULL, "TRB Header");

    tr_hdr.scheme_id = tvb_get_letoh24(tvb, tvb_offset);
    proto_tree_add_item(tr_header_tree, hf_id[2], tvb, tvb_offset, 4, ENC_LITTLE_ENDIAN);
    tvb_offset += 4;

    /* Skip the timestamp */
    tvb_offset += 4;
    tvb_offset += 4;

    tr_hdr.version = tvb_get_letohs(tvb, tvb_offset);
    proto_tree_add_item(tr_header_tree, hf_id[0], tvb, tvb_offset, 2, ENC_LITTLE_ENDIAN);
    tvb_offset += 2;

    tr_hdr.format = tvb_get_letohs(tvb, tvb_offset);
    proto_tree_add_item(tr_header_tree, hf_id[1], tvb, tvb_offset, 2, ENC_LITTLE_ENDIAN);
    tvb_offset += 2;

    /* Skip the resderved field */
    tvb_offset += 4;

    tr_body_tree = proto_tree_add_subtree(tr_tree, tvb, tvb_offset, 16, ett_trb_data, NULL, "Log Data");

    process_dsv_data(tvb, pinfo, tr_body_tree, tvb_offset, &tr_hdr, 0); // ToDo: Add support for multiple schemes

    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_INFO, info_string);

    return tvb_captured_length(tvb);
}

void
proto_register_trb(void)
{
    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_bds,
        &ett_trb_header,
        &ett_trb_data
    };

    proto_trb = proto_register_protocol(
        "Text Record Block", /* name       */
        "TRB",      /* short name */
        "trb"       /* abbrev     */
    );

    proto_register_subtree_array(ett, array_length(ett));

    register_init_routine(init_trb);
    register_cleanup_routine(clean_up);

    register_pcapng_block_type_handler((guint)BLOCK_TYPE_TSDB, tsdb_read_block, NULL);
    register_pcapng_block_type_handler((guint)BLOCK_TYPE_TRB, trb_read_block, NULL);


    //    wtap_opttype_register_custom_block_type("TSDB", "Text Source Descriptor Block",
    //        tsdb_create, tsdb_free_mand, tsdb_copy_mand);
}

void proto_reg_handoff_trb(void)
{
    static dissector_handle_t trb_handle;

    trb_handle = create_dissector_handle(dissect_trb, proto_trb);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USER11, trb_handle);

    /* Need to initialise the first entry in the hf_id array as this is used to check if it needs to be registered */
    hf_id[0] = -1;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
