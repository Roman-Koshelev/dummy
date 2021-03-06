/* packet-tftp2.c
 * Routines for tftp2 packet dissection
 *
 * Richard Sharpe <rsharpe@ns.aus.com>
 * Craig Newell <CraigN@cheque.uq.edu.au>
 *      RFC2347 TFTP2 Option Extension
 * Joerg Mayer (see AUTHORS file)
 *      RFC2348 TFTP2 Blocksize Option
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-bootp.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Documentation:
 * RFC 1350: THE TFTP2 PROTOCOL (REVISION 2)
 * RFC 2090: TFTP2 Multicast Option
 *           (not yet implemented)
 * RFC 2347: TFTP2 Option Extension
 * RFC 2348: TFTP2 Blocksize Option
 * RFC 2349: TFTP2 Timeout Interval and Transfer Size Options
 *           (not yet implemented)
 */

#include "config.h"

#include <stdlib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/export_object.h>
#include <epan/reassemble.h>

#include "packet-tftp2.h"

void proto_register_tftp2(void);

/* Things we may want to remember for a whole conversation */
typedef struct _tftp2_conv_info_t {
  guint16      blocksize;
  const guint8 *source_file, *destination_file;

  /* Sequence analysis */
  guint        next_block_num;
  gboolean     blocks_missing;

  /* When exporting file object, build up list of data blocks here */
  guint        next_tap_block_num;
  GSList       *block_list;
  guint        file_length;

  /* Assembly of fragments */
  guint        next_reassembled_block_num;
  guint        reassembly_id;
} tftp2_conv_info_t;


static int proto_tftp2 = -1;
static int hf_tftp2_opcode = -1;
static int hf_tftp2_source_file = -1;
static int hf_tftp2_destination_file = -1;
static int hf_tftp2_transfer_type = -1;
static int hf_tftp2_blocknum = -1;
static int hf_tftp2_error_code = -1;
static int hf_tftp2_error_string = -1;
static int hf_tftp2_option_name = -1;
static int hf_tftp2_option_value = -1;
static int hf_tftp2_data = -1;

static int hf_tftp2_fragments = -1;
static int hf_tftp2_fragment = -1;
static int hf_tftp2_fragment_overlap = -1;
static int hf_tftp2_fragment_overlap_conflicts = -1;
static int hf_tftp2_fragment_multiple_tails = -1;
static int hf_tftp2_fragment_too_long_fragment = -1;
static int hf_tftp2_fragment_error = -1;
static int hf_tftp2_fragment_count = -1;
static int hf_tftp2_reassembled_in = -1;
static int hf_tftp2_reassembled_length = -1;
static int hf_tftp2_reassembled_data = -1;

static gint ett_tftp2 = -1;
static gint ett_tftp2_option = -1;

static gint ett_tftp2_fragment = -1;
static gint ett_tftp2_fragments = -1;

static expert_field ei_tftp2_blocksize_range = EI_INIT;

static dissector_handle_t tftp2_handle;

static heur_dissector_list_t heur_subdissector_list;
static reassembly_table tftp2_reassembly_table;

static guint32 global_reassembly_id_counter = 0;

static const fragment_items tftp2_frag_items = {
  /* Fragment subtrees */
  &ett_tftp2_fragment,
  &ett_tftp2_fragments,
  /* Fragment fields */
  &hf_tftp2_fragments,
  &hf_tftp2_fragment,
  &hf_tftp2_fragment_overlap,
  &hf_tftp2_fragment_overlap_conflicts,
  &hf_tftp2_fragment_multiple_tails,
  &hf_tftp2_fragment_too_long_fragment,
  &hf_tftp2_fragment_error,
  &hf_tftp2_fragment_count,
  /* Reassembled in field */
  &hf_tftp2_reassembled_in,
  /* Reassembled length field */
  &hf_tftp2_reassembled_length,
  &hf_tftp2_reassembled_data,
  /* Tag */
  "TFTP2 fragments"
};

#define UDP_PORT_TFTP2_RANGE    "59"

void proto_reg_handoff_tftp2 (void);

/* User definable values */
static range_t *global_tftp2_port_range = NULL;

/* minimum length is an ACK message of 4 bytes */
#define MIN_HDR_LEN  4

#define TFTP2_RRQ        1
#define TFTP2_WRQ        2
#define TFTP2_DATA       3
#define TFTP2_ACK        4
#define TFTP2_ERROR      5
#define TFTP2_OACK       6
#define TFTP2_INFO     255

static const value_string tftp2_opcode_vals[] = {
  { TFTP2_RRQ,   "Read Request" },
  { TFTP2_WRQ,   "Write Request" },
  { TFTP2_DATA,  "Data Packet" },
  { TFTP2_ACK,   "Acknowledgement" },
  { TFTP2_ERROR, "Error Code" },
  { TFTP2_OACK,  "Option Acknowledgement" },
  { TFTP2_INFO,  "Information (MSDP)" },
  { 0,          NULL }
};

#define TFTP2_ERR_NOT_DEF      0
#define TFTP2_ERR_NOT_FOUND    1
#define TFTP2_ERR_NOT_ALLOWED  2
#define TFTP2_ERR_DISK_FULL    3
#define TFTP2_ERR_BAD_OP       4
#define TFTP2_ERR_BAD_ID       5
#define TFTP2_ERR_EXISTS       6
#define TFTP2_ERR_NO_USER      7
#define TFTP2_ERR_OPT_FAIL     8

static const value_string tftp2_error_code_vals[] = {
  { TFTP2_ERR_NOT_DEF,     "Not defined" },
  { TFTP2_ERR_NOT_FOUND,   "File not found" },
  { TFTP2_ERR_NOT_ALLOWED, "Access violation" },
  { TFTP2_ERR_DISK_FULL,   "Disk full or allocation exceeded" },
  { TFTP2_ERR_BAD_OP,      "Illegal TFTP2 Operation" },
  { TFTP2_ERR_BAD_ID,      "Unknown transfer ID" }, /* Does not cause termination */
  { TFTP2_ERR_EXISTS,      "File already exists" },
  { TFTP2_ERR_NO_USER,     "No such user" },
  { TFTP2_ERR_OPT_FAIL,    "Option negotiation failed" },
  { 0, NULL }
};

static int tftp2_eo_tap = -1;

/* A list of block list entries to delete from cleanup callback when window is closed. */
typedef struct eo_info_dynamic_t {
    gchar  *filename;
    GSList *block_list;
} eo_info_dynamic_t;
static GSList *s_dynamic_info_list = NULL;

/* Used for TFTP2 Export Object feature */
typedef struct _tftp2_eo_t {
	guint32  pkt_num;
	gchar    *filename;
	guint32  payload_len;
	GSList   *block_list;
} tftp2_eo_t;

/* Tap function */
static gboolean
tftp2_eo_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data)
{
  export_object_list_t *object_list = (export_object_list_t *)tapdata;
  const tftp2_eo_t *eo_info = (const tftp2_eo_t *)data;
  export_object_entry_t *entry;

  GSList *block_iterator;
  guint  payload_data_offset = 0;
  eo_info_dynamic_t *dynamic_info;

  /* These values will be freed when the Export Object window is closed. */
  entry = g_new(export_object_entry_t, 1);

  /* Remember which frame had the last block of the file */
  entry->pkt_num = pinfo->num;

  /* Copy filename */
  entry->filename = g_path_get_basename(eo_info->filename);

  /* Iterate over list of blocks and concatenate into contiguous memory */
  entry->payload_len = eo_info->payload_len;
  entry->payload_data = (guint8 *)g_try_malloc((gsize)entry->payload_len);
  for (block_iterator = eo_info->block_list; block_iterator; block_iterator = block_iterator->next) {
    file_block_t *block = (file_block_t*)block_iterator->data;
    memcpy(entry->payload_data + payload_data_offset,
               block->data,
               block->length);
    payload_data_offset += block->length;
  }

  /* These 2 fields not used */
  entry->hostname = NULL;
  entry->content_type = NULL;

  /* Add to list of entries to be cleaned up.  eo_info is only packet scope, so
     need to make list only of block list now */
  dynamic_info = g_new(eo_info_dynamic_t, 1);
  dynamic_info->filename = eo_info->filename;
  dynamic_info->block_list = eo_info->block_list;
  s_dynamic_info_list = g_slist_append(s_dynamic_info_list, (eo_info_dynamic_t*)dynamic_info);

  /* Pass out entry to the GUI */
  object_list->add_entry(object_list->gui_data, entry);

  return TRUE; /* State changed - window should be redrawn */
}

/* Clean up the stored parts of a single tapped entry */
static void cleanup_tftp2_eo(eo_info_dynamic_t *dynamic_info)
{
  GSList *block_iterator;
  /* Free the filename */
  g_free(dynamic_info->filename);

  /* Walk list of block items */
  for (block_iterator = dynamic_info->block_list; block_iterator; block_iterator = block_iterator->next) {
    file_block_t *block = (file_block_t*)(block_iterator->data);
    /* Free block data */
    wmem_free(NULL, block->data);

    /* Free block itself */
    g_free(block);
  }
}

/* Callback for freeing up data supplied with taps.  The taps themselves only have
   packet scope, so only store/free dynamic memory pointers */
static void tftp2_eo_cleanup(void)
{
  /* Cleanup each entry in the global list */
  GSList *dynamic_iterator;
  for (dynamic_iterator = s_dynamic_info_list; dynamic_iterator; dynamic_iterator = dynamic_iterator->next) {
    eo_info_dynamic_t *dynamic_info = (eo_info_dynamic_t*)dynamic_iterator->data;
    cleanup_tftp2_eo(dynamic_info);
  }
  /* List is empty again */
  s_dynamic_info_list = NULL;
}

static void
tftp2_dissect_options(tvbuff_t *tvb, packet_info *pinfo, int offset,
                     proto_tree *tree, guint16 opcode, tftp2_conv_info_t *tftp2_info)
{
  int         option_len, value_len;
  int         value_offset;
  const char *optionname;
  const char *optionvalue;
  proto_tree *opt_tree;

  while (tvb_offset_exists(tvb, offset)) {
    /* option_len and value_len include the trailing 0 byte */
    option_len = tvb_strsize(tvb, offset);
    value_offset = offset + option_len;
    value_len = tvb_strsize(tvb, value_offset);
    /* use xxx_len-1 to exclude the trailing 0 byte, it would be
       displayed as nonprinting character
       tvb_format_text() creates a temporary 0-terminated buffer */
    optionname = tvb_format_text(tvb, offset, option_len-1);
    optionvalue = tvb_format_text(tvb, value_offset, value_len-1);
    opt_tree = proto_tree_add_subtree_format(tree, tvb, offset, option_len+value_len,
                                   ett_tftp2_option, NULL, "Option: %s = %s", optionname, optionvalue);

    proto_tree_add_item(opt_tree, hf_tftp2_option_name, tvb, offset,
                        option_len, ENC_ASCII|ENC_NA);
    proto_tree_add_item(opt_tree, hf_tftp2_option_value, tvb, value_offset,
                        value_len, ENC_ASCII|ENC_NA);

    offset += option_len + value_len;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s=%s",
                    optionname, optionvalue);

    /* Special code to handle individual options */
    if (!g_ascii_strcasecmp((const char *)optionname, "blksize") &&
        opcode == TFTP2_OACK) {
      gint blocksize = (gint)strtol((const char *)optionvalue, NULL, 10);
      if (blocksize < 8 || blocksize > 65464) {
        expert_add_info(pinfo, NULL, &ei_tftp2_blocksize_range);
      } else {
        tftp2_info->blocksize = blocksize;
      }
    }
  }
}

static void cleanup_tftp2_blocks(tftp2_conv_info_t *conv)
{
    GSList *block_iterator;

    /* Walk list of block items */
    for (block_iterator = conv->block_list; block_iterator; block_iterator = block_iterator->next) {
        file_block_t *block = (file_block_t*)block_iterator->data;
        /* Free block data */
        wmem_free(NULL, block->data);

        /* Free block itself */
        g_free(block);
    }
    conv->block_list = NULL;
    conv->file_length = 0;
}


static void dissect_tftp2_message(tftp2_conv_info_t *tftp2_info,
                                 tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *tree)
{
  proto_tree *tftp2_tree;
  proto_item *ti;
  gint        offset    = 0;
  guint16     opcode;
  guint16     bytes;
  guint16     blocknum;
  guint       i1;
  guint16     error;
  tvbuff_t    *data_tvb = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TFTP2");

  /* Protocol root */
  ti = proto_tree_add_item(tree, proto_tftp2, tvb, offset, -1, ENC_NA);
  tftp2_tree = proto_item_add_subtree(ti, ett_tftp2);

  /* Opcode */
  opcode = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tftp2_tree, hf_tftp2_opcode, tvb, offset, 2, opcode);
  col_add_str(pinfo->cinfo, COL_INFO,
              val_to_str(opcode, tftp2_opcode_vals, "Unknown (0x%04x)"));
  offset += 2;

  /* read and write requests contain file names
     for other messages, we add the filenames from the conversation */
  if (opcode!=TFTP2_RRQ && opcode!=TFTP2_WRQ) {
    if (tftp2_info->source_file) {
      ti = proto_tree_add_string(tftp2_tree, hf_tftp2_source_file, tvb,
          0, 0, tftp2_info->source_file);
      PROTO_ITEM_SET_GENERATED(ti);
    }

    if (tftp2_info->destination_file) {
      ti = proto_tree_add_string(tftp2_tree, hf_tftp2_destination_file, tvb,
          0, 0, tftp2_info->destination_file);
      PROTO_ITEM_SET_GENERATED(ti);
    }
  }

  switch (opcode) {

  case TFTP2_RRQ:
    i1 = tvb_strsize(tvb, offset);
    proto_tree_add_item_ret_string(tftp2_tree, hf_tftp2_source_file,
                        tvb, offset, i1, ENC_ASCII|ENC_NA, wmem_file_scope(), &tftp2_info->source_file);

    /* we either have a source file name (for read requests) or a
       destination file name (for write requests) 
       when we set one of the names, we clear the other */
    tftp2_info->destination_file = NULL;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", File: %s",
                    tvb_format_text(tvb, offset, i1 - 1));

    offset += i1;

    i1 = tvb_strsize(tvb, offset);
    proto_tree_add_item(tftp2_tree, hf_tftp2_transfer_type,
                        tvb, offset, i1, ENC_ASCII|ENC_NA);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Transfer type: %s",
                    tvb_format_text(tvb, offset, i1 - 1));

    offset += i1;

    tftp2_dissect_options(tvb, pinfo,  offset, tftp2_tree,
                         opcode, tftp2_info);
    break;

  case TFTP2_WRQ:
    i1 = tvb_strsize(tvb, offset);
    proto_tree_add_item_ret_string(tftp2_tree, hf_tftp2_destination_file,
                        tvb, offset, i1, ENC_ASCII|ENC_NA, wmem_file_scope(), &tftp2_info->destination_file);

    tftp2_info->source_file = NULL; /* see above */

    col_append_fstr(pinfo->cinfo, COL_INFO, ", File: %s",
                    tvb_format_text(tvb, offset, i1 - 1));

    offset += i1;

    i1 = tvb_strsize(tvb, offset);
    proto_tree_add_item(tftp2_tree, hf_tftp2_transfer_type,
                        tvb, offset, i1, ENC_ASCII|ENC_NA);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Transfer type: %s",
                    tvb_format_text(tvb, offset, i1 - 1));

    offset += i1;

    tftp2_dissect_options(tvb, pinfo, offset, tftp2_tree,
                         opcode,  tftp2_info);
    break;

  case TFTP2_INFO:
    tftp2_dissect_options(tvb, pinfo, offset, tftp2_tree,
                         opcode,  tftp2_info);
    break;

  case TFTP2_DATA:
    blocknum = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tftp2_tree, hf_tftp2_blocknum, tvb, offset, 2,
                        blocknum);

    /* Sequence analysis on blocknums (first pass only) */
    if (!pinfo->fd->flags.visited) {
      if (blocknum > tftp2_info->next_block_num) {
        /* There is a gap.  Don't try to recover from this. */
        tftp2_info->next_block_num = blocknum + 1;
        tftp2_info->blocks_missing = TRUE;
        /* TODO: add info to a result table for showing expert info in later passes */
      }
      else if (blocknum == tftp2_info->next_block_num) {
        /* OK, inc what we expect next */
        tftp2_info->next_block_num++;
      }
    }
    offset += 2;

    /* Show number of bytes in this block, and whether it is the end of the file */
    bytes = tvb_reported_length_remaining(tvb, offset);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Block: %i%s",
                    blocknum,
                    (bytes < tftp2_info->blocksize)?" (last)":"" );

    if (!tftp2_info->blocks_missing) {
      if (blocknum == 1) {
        tftp2_info->next_reassembled_block_num = 1;
      }

      if (blocknum != tftp2_info->next_reassembled_block_num) {
        if (bytes > 0) {
          data_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, bytes);
          call_data_dissector(data_tvb, pinfo, tree);
        }
      } else {
        tftp2_info->next_reassembled_block_num++;

        gboolean   save_fragmented;
        tvbuff_t* new_tvb = NULL;
        tvbuff_t* next_tvb = NULL;
        fragment_head *frag_msg = NULL;

        save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;

        frag_msg = fragment_add_seq_check(
            &tftp2_reassembly_table, tvb, offset, pinfo, tftp2_info->reassembly_id, NULL,
            tftp2_info->next_reassembled_block_num - 2, tvb_captured_length_remaining(tvb, offset),
            !(bytes < tftp2_info->blocksize));

        new_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled TFTP2",
                                        frag_msg, &tftp2_frag_items,
                                        NULL, tftp2_tree);
        if (new_tvb) { /* take it all */
          tftp2_info->next_reassembled_block_num = 1;
          next_tvb = new_tvb;

          heur_dtbl_entry_t *hdtbl_entry = NULL;
          void* data = (void*)((tftp2_info->source_file == NULL) ? tftp2_info->destination_file : tftp2_info->source_file);
          if (!dissector_try_heuristic(heur_subdissector_list,
                                       next_tvb, pinfo, tree,
                                       &hdtbl_entry, data)) {
            if (bytes > 0) {
              data_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, bytes);
              call_data_dissector(data_tvb, pinfo, tree);
            }
          }
        } else { /* make a new subset */
          if (bytes > 0) {
            data_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, bytes);
            call_data_dissector(data_tvb, pinfo, tree);
          }
        }
        pinfo->fragmented = save_fragmented;
      }
    } else {
      /* Show data in tree */
      if (bytes > 0) {
        data_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, bytes);
        call_data_dissector(data_tvb, pinfo, tree);
      }
    }

    /* If Export Object tap is listening, need to accumulate blocks info list
       to send to tap. But if already know there are blocks missing, there is no
       point in trying. */
    if (have_tap_listener(tftp2_eo_tap) && !tftp2_info->blocks_missing) {
      file_block_t *block;

      if (blocknum == 1) {
        /* Reset data for this conversation, freeing any accumulated blocks! */
        cleanup_tftp2_blocks(tftp2_info);
        tftp2_info->next_tap_block_num = 1;
      }

      if (blocknum != tftp2_info->next_tap_block_num) {
        /* Ignore.  Could be missing frames, or just clicking previous frame */
        return;
      }

      if (bytes > 0) {
        /* Create a block for this block */
        block = (file_block_t*)g_malloc(sizeof(file_block_t));
        block->length = bytes;
        block->data = tvb_memdup(NULL, data_tvb, 0, bytes);

        /* Add to the end of the list (does involve traversing whole list..) */
        tftp2_info->block_list = g_slist_append(tftp2_info->block_list, block);
        tftp2_info->file_length += bytes;

        /* Look for next blocknum next time */
        tftp2_info->next_tap_block_num++;
      }

      /* Tap export object only when reach end of file */
      if (bytes < tftp2_info->blocksize) {
        tftp2_eo_t        *eo_info;

        /* If don't have a filename, won't tap file info */
        if ((tftp2_info->source_file == NULL) && (tftp2_info->destination_file == NULL)) {
            cleanup_tftp2_blocks(tftp2_info);
            return;
        }

        /* Create the eo_info to pass to the listener */
        eo_info = wmem_new(wmem_packet_scope(), tftp2_eo_t);

        /* Set filename */
        if (tftp2_info->source_file) {
          eo_info->filename = g_strdup(tftp2_info->source_file);
        }
        else if (tftp2_info->destination_file) {
          eo_info->filename = g_strdup(tftp2_info->destination_file);
        }

        /* Send block list, which will be combined and freed at tap. */
        eo_info->payload_len = tftp2_info->file_length;
        eo_info->pkt_num = blocknum;
        eo_info->block_list = tftp2_info->block_list;

        /* Send to tap */
        tap_queue_packet(tftp2_eo_tap, pinfo, eo_info);

        /* Have sent, so forget list of blocks, and only pay attention if we
           get back to the first block again. */
        tftp2_info->block_list = NULL;
        tftp2_info->next_tap_block_num = 1;
      }
    }
    break;

  case TFTP2_ACK:
    blocknum = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tftp2_tree, hf_tftp2_blocknum, tvb, offset, 2,
                        blocknum);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Block: %i",
                    blocknum);
    break;

  case TFTP2_ERROR:
    error = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tftp2_tree, hf_tftp2_error_code, tvb, offset, 2,
                        error);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Code: %s",
                    val_to_str(error, tftp2_error_code_vals, "Unknown (%u)"));

    offset += 2;

    i1 = tvb_strsize(tvb, offset);
    proto_tree_add_item(tftp2_tree, hf_tftp2_error_string, tvb, offset,
                        i1, ENC_ASCII|ENC_NA);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Message: %s",
                    tvb_format_text(tvb, offset, i1 - 1));

    expert_add_info(pinfo, NULL, &ei_tftp2_blocksize_range);
    break;

  case TFTP2_OACK:
    tftp2_dissect_options(tvb, pinfo, offset, tftp2_tree,
                         opcode, tftp2_info);
    break;

  default:
    proto_tree_add_item(tftp2_tree, hf_tftp2_data, tvb, offset, -1, ENC_NA);
    break;

  }
}

static gboolean
dissect_embeddedtftp2_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  /* Used to dissect TFTP2 packets where one can not assume
     that the TFTP2 is the only protocol used by that port, and
     that TFTP2 may not be carried by UDP */
  conversation_t   *conversation = NULL;
  guint16           opcode;
  tftp2_conv_info_t *tftp2_info;

  /*
   * We need to verify it could be a TFTP2 message before creating a conversation
   */

  if (tvb_captured_length(tvb) < MIN_HDR_LEN)
    return FALSE;

  opcode = tvb_get_ntohs(tvb, 0);

  switch (opcode) {
    case TFTP2_RRQ:
    case TFTP2_WRQ:
      /* These 2 opcodes have a NULL-terminated source file name after opcode. Verify */
      {
        gint char_offset = 1;
        while (tvb_captured_length_remaining(tvb, char_offset)) {
          gchar c = (gchar)tvb_get_guint8(tvb, char_offset++);
          if (c == '\0') {
            /* NULL termination found - continue with dissection */
            break;
          }
          else if (!g_ascii_isprint(c)) {
            /* Not part of a file name - give up now */
            return FALSE;
          }
        }
        /* Would have to have a short capture length to not include the whole filename,
           but fall through here anyway rather than returning FALSE */
     }
     /* Intentionally dropping through here... */
    case TFTP2_DATA:
    case TFTP2_ACK:
    case TFTP2_OACK:
    case TFTP2_INFO:
      break;
    case TFTP2_ERROR:
      /* for an error, we can verify the error code is legit */
      switch (tvb_get_ntohs(tvb, 2)) {
        case TFTP2_ERR_NOT_DEF:
        case TFTP2_ERR_NOT_FOUND:
        case TFTP2_ERR_NOT_ALLOWED:
        case TFTP2_ERR_DISK_FULL:
        case TFTP2_ERR_BAD_OP:
        case TFTP2_ERR_BAD_ID:
        case TFTP2_ERR_EXISTS:
        case TFTP2_ERR_NO_USER:
        case TFTP2_ERR_OPT_FAIL:
          break;
        default:
          return FALSE;
      }
      break;
    default:
      return FALSE;
  }

  conversation = find_or_create_conversation(pinfo);

  tftp2_info = (tftp2_conv_info_t *)conversation_get_proto_data(conversation, proto_tftp2);
  if (!tftp2_info) {
    tftp2_info = wmem_new(wmem_file_scope(), tftp2_conv_info_t);
    tftp2_info->blocksize = 512; /* TFTP2 default block size */
    tftp2_info->source_file = NULL;
    tftp2_info->destination_file = NULL;
    tftp2_info->next_block_num = 1;
    tftp2_info->blocks_missing = FALSE;
    tftp2_info->next_tap_block_num = 1;
    tftp2_info->block_list = NULL;
    tftp2_info->file_length = 0;
    tftp2_info->next_reassembled_block_num = 1;
    tftp2_info->reassembly_id = global_reassembly_id_counter++;

    conversation_add_proto_data(conversation, proto_tftp2, tftp2_info);
  }

  dissect_tftp2_message(tftp2_info, tvb, pinfo, tree);
  return TRUE;
}

static int
dissect_tftp2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  conversation_t   *conversation = NULL;
  tftp2_conv_info_t *tftp2_info;

  /*
   * The first TFTP2 packet goes to the TFTP2 port; the second one
   * comes from some *other* port, but goes back to the same
   * IP address and port as the ones from which the first packet
   * came; all subsequent packets go between those two IP addresses
   * and ports.
   *
   * If this packet went to the TFTP2 port (either to one of the ports
   * set in the preferences or to a port set via Decode As), we check
   * to see if there's already a conversation with one address/port pair
   * matching the source IP address and port of this packet,
   * the other address matching the destination IP address of this
   * packet, and any destination port.
   *
   * If not, we create one, with its address 1/port 1 pair being
   * the source address/port of this packet, its address 2 being
   * the destination address of this packet, and its port 2 being
   * wildcarded, and give it the TFTP2 dissector as a dissector.
   */
  if (value_is_in_range(global_tftp2_port_range, pinfo->destport) ||
      (pinfo->match_uint == pinfo->destport)) {
    conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_UDP,
                                     pinfo->srcport, 0, NO_PORT_B);
    if( (conversation == NULL) || (conversation_get_dissector(conversation, pinfo->num) != tftp2_handle) ){
      conversation = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_UDP,
                                      pinfo->srcport, 0, NO_PORT2);
      conversation_set_dissector(conversation, tftp2_handle);
    }
  } else {
    conversation = find_conversation_pinfo(pinfo, 0);
    if( (conversation == NULL) || (conversation_get_dissector(conversation, pinfo->num) != tftp2_handle) ){
      conversation = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_UDP,
                                      pinfo->destport, pinfo->srcport, 0);
      conversation_set_dissector(conversation, tftp2_handle);
    } else if (conversation->options & NO_PORT_B) {
      if (pinfo->destport == conversation_key_port1(conversation->key_ptr))
        conversation_set_port2(conversation, pinfo->srcport);
      else
        return 0;
    }
  }
  tftp2_info = (tftp2_conv_info_t *)conversation_get_proto_data(conversation, proto_tftp2);
  if (!tftp2_info) {
    tftp2_info = wmem_new(wmem_file_scope(), tftp2_conv_info_t);
    tftp2_info->blocksize = 512; /* TFTP2 default block size */
    tftp2_info->source_file = NULL;
    tftp2_info->destination_file = NULL;
    tftp2_info->next_block_num = 1;
    tftp2_info->blocks_missing = FALSE;
    tftp2_info->next_tap_block_num = 1;
    tftp2_info->block_list = NULL;
    tftp2_info->file_length = 0;
    tftp2_info->next_reassembled_block_num = 1;
    tftp2_info->reassembly_id = global_reassembly_id_counter++;
    conversation_add_proto_data(conversation, proto_tftp2, tftp2_info);
  }

  dissect_tftp2_message(tftp2_info, tvb, pinfo, tree);
  return tvb_captured_length(tvb);
}


static void
apply_tftp2_prefs(void) {
  global_tftp2_port_range = prefs_get_range_value("tftp2", "udp.port");
}

void
proto_register_tftp2(void)
{
  static hf_register_info hf[] = {
    { &hf_tftp2_opcode,
      { "Opcode",             "tftp2.opcode",
        FT_UINT16, BASE_DEC, VALS(tftp2_opcode_vals), 0x0,
        "TFTP2 message type", HFILL }},

    { &hf_tftp2_source_file,
      { "Source File",        "tftp2.source_file",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "TFTP2 source file name", HFILL }},

    { &hf_tftp2_destination_file,
      { "DESTINATION File",   "tftp2.destination_file",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "TFTP2 source file name", HFILL }},

    { &hf_tftp2_transfer_type,
      { "Type",               "tftp2.type",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "TFTP2 transfer type", HFILL }},

    { &hf_tftp2_blocknum,
      { "Block",              "tftp2.block",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Block number", HFILL }},

    { &hf_tftp2_error_code,
      { "Error code",         "tftp2.error.code",
        FT_UINT16, BASE_DEC, VALS(tftp2_error_code_vals), 0x0,
        "Error code in case of TFTP2 error message", HFILL }},

    { &hf_tftp2_error_string,
      { "Error message",      "tftp2.error.message",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "Error string in case of TFTP2 error message", HFILL }},

    { &hf_tftp2_option_name,
      { "Option name",        "tftp2.option.name",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_tftp2_option_value,
      { "Option value",       "tftp2.option.value",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_tftp2_data,
      { "Data",       "tftp2.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

      {&hf_tftp2_fragments,
       {"TFTP2 fragments", "tftp2.fragments", FT_NONE, BASE_NONE,
        NULL, 0x00, NULL, HFILL}},

      {&hf_tftp2_fragment,
       {"TFTP2 fragment", "tftp2.fragment", FT_FRAMENUM,
        BASE_NONE, NULL, 0x00, NULL, HFILL}},

      {&hf_tftp2_fragment_overlap,
       {"TFTP2 fragment overlap", "tftp2.fragment.overlap",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL}},

      {&hf_tftp2_fragment_overlap_conflicts,
       {"TFTP2 fragment overlapping with conflicting data",
        "tftp2.fragment.overlap.conflicts", FT_BOOLEAN, 0, NULL,
        0x00, NULL, HFILL}},

      {&hf_tftp2_fragment_multiple_tails,
       {"TFTP2 has multiple tail fragments",
        "tftp2.fragment.multiple_tails", FT_BOOLEAN, 0, NULL, 0x00,
        NULL, HFILL}},

      {&hf_tftp2_fragment_too_long_fragment,
       {"TFTP2 fragment too long",
        "tftp2.fragment.too_long_fragment", FT_BOOLEAN, 0, NULL,
        0x00, NULL, HFILL}},

      {&hf_tftp2_fragment_error,
       {"TFTP2 defragmentation error", "tftp2.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL}},

      {&hf_tftp2_fragment_count,
       {"TFTP2 fragment count", "tftp2.fragment.count",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}},

      {&hf_tftp2_reassembled_in,
       {"Reassembled TFTP2 in frame", "tftp2.reassembled.in", FT_FRAMENUM,
        BASE_NONE, NULL, 0x00, NULL, HFILL}},

      {&hf_tftp2_reassembled_length,
       {"Reassembled TFTP2 length", "tftp2.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x00, "The total length of the reassembled payload", HFILL}},

      {&hf_tftp2_reassembled_data,
       {"Reassembled TFTP2 data", "tftp2.reassembled.data", FT_BYTES,
        BASE_NONE, NULL, 0x0, "The reassembled payload", HFILL}},
  };
  static gint *ett[] = {
    &ett_tftp2,
    &ett_tftp2_option,
    &ett_tftp2_fragment,
    &ett_tftp2_fragments,
  };

  static ei_register_info ei[] = {
     { &ei_tftp2_blocksize_range, { "tftp2.blocksize_range", PI_RESPONSE_CODE, PI_WARN, "TFTP2 blocksize out of range", EXPFILL }},
  };

  expert_module_t* expert_tftp2;

  proto_tftp2 = proto_register_protocol("Trivial File Transfer Protocol v2", "TFTP2", "tftp2");
  proto_register_field_array(proto_tftp2, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_tftp2 = expert_register_protocol(proto_tftp2);
  expert_register_field_array(expert_tftp2, ei, array_length(ei));

  heur_subdissector_list = register_heur_dissector_list("tftp2", proto_tftp2);
  reassembly_table_register(&tftp2_reassembly_table, &addresses_reassembly_table_functions);

  tftp2_handle = register_dissector("tftp2", dissect_tftp2, proto_tftp2);

  prefs_register_protocol(proto_tftp2, apply_tftp2_prefs);

  /* Register the tap for the "Export Object" function */
  tftp2_eo_tap = register_export_object(proto_tftp2, tftp2_eo_packet, tftp2_eo_cleanup);
}

void
proto_reg_handoff_tftp2(void)
{
  heur_dissector_add("stun", dissect_embeddedtftp2_heur, "TFTP2 over TURN", "tftp2_stun", proto_tftp2, HEURISTIC_ENABLE);

  dissector_add_uint_range_with_preference("udp.port", UDP_PORT_TFTP2_RANGE, tftp2_handle);
  apply_tftp2_prefs();
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */

