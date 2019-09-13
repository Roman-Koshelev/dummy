#include <stdio.h>

#include <config.h>

#include <epan/packet.h>
#include <epan/conversation.h>

/* this enumeration represents the A615a and A665 file types */
enum A615A_SUFFIX {
  LCI = 0,
  LCL,
  LCS,
  LNA,
  LND,
  LNL,
  LNO,
  LNR,
  LNS,
  LUB, /* Arinc 665 */
  LUH, /* Arinc 665 */
  LUI,
  LUM, /* Arinc 665 */
  LUP, /* Arinc 665 */
  LUR,
  LUS
};

/* this item holds file extension strings */
static const char *a615a_file_ext[16] = {
    "LCI", "LCL", "LCS", "LNA", "LND", "LNL", "LNO", "LNR",
    "LNS", "LUB", "LUH", "LUI", "LUM", "LUP", "LUR", "LUS"};

/* this item holds A615a operation status codes */
static const value_string a615a_op_status_codes[] = {
    {0x1, "Accepted, not yet started"},
    {0x2, "Operation in progress"},
    {0x3, "Operation completed without error"},
    {0x4, "Operation in progress, details in status description"},
    {0x1000, "Operation denied, reason in status description"},
    {0x1002, "Operation not supported by the target"},
    {0x1003,
     "Operation aborted by target hardware, info in status description"},
    {0x1004, "Operation aborted by target on Dataloader error message"},
    {0x1005, "Operation aborted by target on operator action"},
    {0x1007,
     "Load of this header file has failed, details in status description"},
    {0, NULL}};

static int proto_a615a = -1;
dissector_handle_t a615a_handle;

/* tree entries */
static gint ett_a615a_fragment = -1;
static gint ett_a615a_fragments = -1;
static gint ett_a615a = -1;
static gint ett_a615a_opt = -1;
static gint ett_a615a_opt_root = -1;
static gint ett_a615a_protocol_root = -1;
static gint ett_a665_protocol_root = -1;

/* arinc 615a nodes */
static int hf_a615a_fragments = -1;
static int hf_a615a_fragment = -1;
static int hf_a615a_fragment_overlap = -1;
static int hf_a615a_fragment_overlap_conflicts = -1;
static int hf_a615a_fragment_multiple_tails = -1;
static int hf_a615a_fragment_too_long_fragment = -1;
static int hf_a615a_fragment_error = -1;
static int hf_a615a_fragment_count = -1;
static int hf_a615a_reassembled_in = -1;
static int hf_a615a_reassembled_length = -1;
static int hf_a615a_file_length = -1;
static int hf_a615a_protocol_version = -1;
static int hf_a615a_counter = -1;
static int hf_a615a_info_op_status = -1;
static int hf_a615a_upload_op_status = -1;
static int hf_a615a_download_op_status = -1;
static int hf_a615a_part_load_op_status = -1;
static int hf_a615a_exception_timer = -1;
static int hf_a615a_estimated_time = -1;
static int hf_a615a_status_description_length = -1;
static int hf_a615a_status_description = -1;
static int hf_a615a_load_ratio = -1;
static int hf_a615a_file_count = -1;
static int hf_a615a_file_name_length = -1;
static int hf_a615a_file_name = -1;
static int hf_a615a_file_description_length = -1;
static int hf_a615a_file_description = -1;
static int hf_a615a_part_number_length = -1;
static int hf_a615a_part_number = -1;
static int hf_a615a_tgt_hw_count = -1;
static int hf_a615a_lit_name_length = -1;
static int hf_a615a_lit_name = -1;
static int hf_a615a_serial_num_length = -1;
static int hf_a615a_serial_num = -1;
static int hf_a615a_part_num_count = -1;
static int hf_a615a_ammendment_len = -1;
static int hf_a615a_ammendment = -1;
static int hf_a615a_designation_len = -1;
static int hf_a615a_designation = -1;
static int hf_a615a_user_data_len = -1;
static int hf_a615a_user_data = -1;

static proto_tree *dissect_a615a_header(tvbuff_t *tvb, packet_info *pinfo, int *offsetPtr, proto_tree *tftp_tree, char *file, char *ext);
static void dissect_a615a_LCL(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree);
static void dissect_a615a_LUS(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree);
static void dissect_a615a_LCS(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree);
static void dissect_a615a_LUI_Common(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root);
static void dissect_a615a_LUI(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree);
static void dissect_a615a_LCI(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree);
static void dissect_a615a_LND(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree);
static void dissect_a615a_LNO(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree);
static void dissect_a615a_LUR(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree);
static void dissect_a615a_LNL(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree);
static void dissect_a615a_LNR(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree);
static void dissect_a615a_LNS(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree);
static void dissect_a615a_LNA(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree);
static void dissect_a615a_a665_msg(tvbuff_t *tb, packet_info *pinfo, int offset, const char *a665Str, proto_tree *tftp_tree);
static void dissect_a615a_protocol_file(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree, int suffix);

/* this routine dissects the common field at the top of an a615a data file */
static proto_tree *
dissect_a615a_header(tvbuff_t *tvb, packet_info *pinfo, int *offsetPtr, proto_tree *tftp_tree, char *file, char *ext)
{
    gint offset = *offsetPtr;
    proto_tree *root;
    root = proto_tree_add_subtree_format(tftp_tree, tvb, offset, -1, ett_a615a_protocol_root, NULL, "%s (%s)", file, ext);
    /* file length */
    guint32 fl = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_file_length, tvb, offset, 4, fl);
    offset += 4;

    /* protocol Version */
    gint end = 2;
    char *protoVersion = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
    proto_tree_add_string(root, hf_a615a_protocol_version, tvb, offset, 2, protoVersion);
    offset += 2;
    *offsetPtr = offset;
    return root;
}

/* this item dissects an LCL file */
static void
dissect_a615a_LCL(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree)
{
    proto_tree *root = dissect_a615a_header(tvb, pinfo, &offset, tftp_tree, "Load Configuration List", "LCL");
    gint end;

    /* target hardware count */
    guint16 numTgtHardware = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_tgt_hw_count, tvb, offset, 2, numTgtHardware);
    offset += 2;
    for (unsigned i = 0; i < numTgtHardware; i++)
    {
        /* literal name length */
        guint8 nameLength = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(root, hf_a615a_lit_name_length, tvb, offset, 1, nameLength);
        offset += 1;

        if (nameLength > 0)
        {
            /* literal name */
            end = nameLength;
            char *name = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
            proto_tree_add_string(root, hf_a615a_lit_name, tvb, offset, nameLength, name);
            offset += nameLength;
        }

        /* serial number length */
        guint8 numLength = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(root, hf_a615a_serial_num_length, tvb, offset, 1, numLength);
        offset += 1;

        if (numLength > 0)
        {
            /* serial number */
            end = numLength;
            char *serialNum = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
            proto_tree_add_string(root, hf_a615a_serial_num, tvb, offset, numLength, serialNum);
            offset += numLength;
        }

        /* part number count */
        guint16 numPartNumbers = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(root, hf_a615a_part_num_count, tvb, offset, 2, numPartNumbers);
        offset += 2;

        for (unsigned i = 0; i < numPartNumbers; i++)
        {
            /* part number length */
            gint partNumLengthOffset = offset;
            guint8 partNumberLength = tvb_get_guint8(tvb, offset);

            offset += 1;

            /* part number */
            gint partNumOffset = offset;
            gint end = partNumberLength;
            char *pnum = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
            offset += partNumberLength;

            proto_tree *part_root;
            part_root = proto_tree_add_subtree_format(root, tvb, partNumLengthOffset, -1, ett_a615a_protocol_root, NULL, "Part %d - %s", i + 1, pnum);
            proto_tree_add_uint(part_root, hf_a615a_part_number_length, tvb, partNumLengthOffset, 1, partNumberLength);
            proto_tree_add_string(part_root, hf_a615a_part_number, tvb, partNumOffset, partNumberLength, pnum);

            /* ammendment length */
            guint8 ammendLen = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(part_root, hf_a615a_ammendment_len, tvb, offset, 1, ammendLen);
            offset += 1;

            if (ammendLen > 0)
            {
                /* ammendment */
                end = ammendLen;
                char *ammend = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
                proto_tree_add_string(part_root, hf_a615a_ammendment, tvb, offset, ammendLen, ammend);
                offset += ammendLen;
            }

            /* part designation length */
            guint8 desLen = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(part_root, hf_a615a_designation_len, tvb, offset, 1, desLen);
            offset += 1;

            if (desLen > 0)
            {
                /* part designation */
                end = desLen;
                char *des = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
                proto_tree_add_string(part_root, hf_a615a_designation, tvb, offset, desLen, des);
                offset += desLen;
            }
        }
    }
}

/* This item dissects an LUS file */
static void
dissect_a615a_LUS(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree)
{
    gint end;
    proto_tree *root = dissect_a615a_header(tvb, pinfo, &offset, tftp_tree, "Load Upload Status", "LUS");

    /* upload op status code */
    guint16 opCode = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_upload_op_status, tvb, offset, 2, opCode);
    offset += 2;

    /* status length */
    guint8 statLength = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_status_description_length, tvb, offset, 1, statLength);
    offset += 1;

    if (statLength > 0)
    {
        /* status description */
        end = statLength;
        char *statDesc = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
        proto_tree_add_string(root, hf_a615a_status_description, tvb, offset, statLength, statDesc);
        offset += statLength;
    }

    /* counter */
    guint16 counter = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_counter, tvb, offset, 2, counter);
    offset += 2;

    /* exception timer */
    guint16 excTimer = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_exception_timer, tvb, offset, 2, excTimer);
    offset += 2;

    /* estimated time */
    guint16 estTime = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_estimated_time, tvb, offset, 2, estTime);
    offset += 2;

    /* load list ratio */
    end = 3;
    char *llr = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
    proto_tree_add_string(root, hf_a615a_load_ratio, tvb, offset, 3, llr);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str(opCode, a615a_op_status_codes, "Unknown (0x%04x)"));
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Load Ratio: %s", llr);

    offset += 3;

    /* header file count */
    guint16 count = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_file_count, tvb, offset, 2, count);
    offset += 2;

    for (unsigned i = 0; i < count; i++)
    {
        /* file name length */
         gint fnameLengthOffset = offset;
        guint8 fnameLength = tvb_get_guint8(tvb, fnameLengthOffset);
        offset += 1;

        /* file name */
        gint fnameOffset = offset;
        end = fnameLength;
        char *fname = tvb_get_stringz_enc(wmem_packet_scope(), tvb, fnameOffset, &end, ENC_ASCII);
        offset += fnameLength;

        proto_tree *part_root;
        part_root = proto_tree_add_subtree_format(root, tvb, fnameLengthOffset, -1, ett_a615a_protocol_root, NULL, "Header %d - %s", i + 1, fname);

        proto_tree_add_uint(part_root, hf_a615a_file_name_length, tvb, fnameLengthOffset, 1, fnameLength);
        proto_tree_add_string(part_root, hf_a615a_file_name, tvb, fnameOffset, fnameLength, fname);

        /* part number length */
        guint8 partNumberLength = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(part_root, hf_a615a_part_number_length, tvb, offset, 1, partNumberLength);
        offset += 1;

        if (partNumberLength > 0)
        {
            /* part number */
            gint end = partNumberLength;
            char *pnum = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
            proto_tree_add_string(part_root, hf_a615a_part_number, tvb, offset, partNumberLength, pnum);
            offset += partNumberLength;
        }

        /* load ratio */
        end = 3;
        char *llr = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
        proto_tree_add_string(part_root, hf_a615a_load_ratio, tvb, offset, 3, llr);
        offset += 3;

        /* soad status code */
        opCode = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(part_root, hf_a615a_part_load_op_status, tvb, offset, 2, opCode);
        offset += 2;

        /* status length */
        statLength = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(part_root, hf_a615a_status_description_length, tvb, offset, 1, statLength);
        offset += 1;

        if (statLength > 0)
        {
            /* status description */
            end = statLength;
            char *statDesc = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
            proto_tree_add_string(part_root, hf_a615a_status_description, tvb, offset, tvb_captured_length_remaining(tvb, offset), statDesc);
            offset += statLength;
        }
    }
}

/* this routine dissects an LCS file */
static void
dissect_a615a_LCS(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree)
{
    proto_tree *root = dissect_a615a_header(tvb, pinfo, &offset, tftp_tree, "Load Control Status", "LCS");
    /* counter */
    guint16 counter = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_counter, tvb, offset, 2, counter);
    offset += 2;

    /* info op status code */
    guint16 opCode = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_info_op_status, tvb, offset, 2, opCode);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str(opCode, a615a_op_status_codes, "Unknown (0x%04x)"));
    offset += 2;

    /* exception timer */
    guint16 excTimer = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_exception_timer, tvb, offset, 2, excTimer);
    offset += 2;

    /* estimated time */
    guint16 estTime = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_estimated_time, tvb, offset, 2, estTime);
    offset += 2;

    /* status length */
    guint8 statLength = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_status_description_length, tvb, offset, 1, statLength);
    offset += 1;

    if (statLength > 0)
    {
        /* status description */
        gint end = statLength;
        char *statDesc = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
        proto_tree_add_string(root, hf_a615a_status_description, tvb, offset, tvb_captured_length_remaining(tvb, offset), statDesc);
        offset += end;
    }
}

/* this routine dissects LUI, LCI, LND, and LNO files */
static void
dissect_a615a_LUI_Common(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    /* op status code */
    guint16 opCode = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_upload_op_status, tvb, offset, 2, opCode);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str(opCode, a615a_op_status_codes, "Unknown (0x%04x)"));
    offset += 2;

    /* status length */
    guint8 statLength = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_status_description_length, tvb, offset, 1, statLength);
    offset += 1;

    if (statLength > 0)
    {
        /* Status description */
        gint end = statLength;
        char *statDesc = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
        proto_tree_add_string(root, hf_a615a_status_description, tvb, offset, tvb_captured_length_remaining(tvb, offset), statDesc);
        offset += end;
    }
}

/* this routine dissects an LUI file */
static void
dissect_a615a_LUI(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree)
{
    proto_tree *root = dissect_a615a_header(tvb, pinfo, &offset, tftp_tree, "Load Upload Initialization", "LUI");
    dissect_a615a_LUI_Common(tvb, pinfo, offset, root);
}

/* this routine diessects an LCI file */
static void
dissect_a615a_LCI(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree)
{
    proto_tree *root = dissect_a615a_header(tvb, pinfo, &offset, tftp_tree, "Load Configuration Initialization", "LCI");
    dissect_a615a_LUI_Common(tvb, pinfo, offset, root);
}

/* this routine dissects an LND file */
static void
dissect_a615a_LND(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree)
{
    proto_tree *root = dissect_a615a_header(tvb, pinfo, &offset, tftp_tree, "Load Downloading Media", "LND");
    dissect_a615a_LUI_Common(tvb, pinfo, offset, root);
}

/* this routine dissects an LNO file */
static void
dissect_a615a_LNO(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree)
{
    proto_tree *root = dissect_a615a_header(tvb, pinfo, &offset, tftp_tree, "Load Downloading Operator", "LNO");
    dissect_a615a_LUI_Common(tvb, pinfo, offset, root);
}

/* this routine diessects an LUR file */
static void
dissect_a615a_LUR(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree)
{
    gint end = -1;
    proto_tree *root = dissect_a615a_header(tvb, pinfo, &offset, tftp_tree, "Load Upload Request", "LUR");

    /* Header file count */
    guint16 count = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_file_count, tvb, offset, 2, count);
    offset += 2;

    for (unsigned i = 0; i < count; i++)
    {
        /* file name length */
        gint fnameLengthOffset = offset;
        guint8 fnameLength = tvb_get_guint8(tvb, fnameLengthOffset);
        offset += 1;
        /* file name */
        gint fnameOffset = offset;
        end = fnameLength;
        char *fname = tvb_get_stringz_enc(wmem_packet_scope(), tvb, fnameOffset, &end, ENC_ASCII);
        offset += fnameLength;

        proto_tree *part_root;
        part_root = proto_tree_add_subtree_format(root, tvb, fnameLengthOffset, -1, ett_a615a_protocol_root, NULL, "Header %d - %s", i + 1, fname);

        proto_tree_add_uint(part_root, hf_a615a_file_name_length, tvb, fnameLengthOffset, 1, fnameLength);
        proto_tree_add_string(part_root, hf_a615a_file_name, tvb, fnameOffset, fnameLength, fname);

        /* part number length */
        guint8 partNumberLength = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(part_root, hf_a615a_part_number_length, tvb, offset, 1, partNumberLength);
        offset += 1;

        if (partNumberLength > 0)
        {
            /* Part number */
            gint end = partNumberLength;
            char *pnum = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
            proto_tree_add_string(part_root, hf_a615a_part_number, tvb, offset, partNumberLength, pnum);
            offset += partNumberLength;
        }
    }
}

/* this routine dissects an LNL file */
static void
dissect_a615a_LNL(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree)
{
    gint end = -1;
    proto_tree *root = dissect_a615a_header(tvb, pinfo, &offset, tftp_tree, "Load Downloading List", "LNL");

    /* file count */
    guint16 count = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_file_count, tvb, offset, 2, count);
    offset += 2;

    for (unsigned i = 0; i < count; i++)
    {
        /* file name length */
        gint fnameLengthOffset = offset;
        guint8 fnameLength = tvb_get_guint8(tvb, fnameLengthOffset);
        offset += 1;

        /* file name */
        gint fnameOffset = offset;
        end = fnameLength;
        char *fname = tvb_get_stringz_enc(wmem_packet_scope(), tvb, fnameOffset, &end, ENC_ASCII);
        offset += fnameLength;

        proto_tree *part_root;
        part_root = proto_tree_add_subtree_format(root, tvb, fnameLengthOffset, -1, ett_a615a_protocol_root, NULL, "Header %d - %s", i + 1, fname);

        proto_tree_add_uint(part_root, hf_a615a_file_name_length, tvb, fnameLengthOffset, 1, fnameLength);
        proto_tree_add_string(part_root, hf_a615a_file_name, tvb, fnameOffset, fnameLength, fname);

        /* file description length */
        guint8 descLength = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(part_root, hf_a615a_file_description_length, tvb, offset, 1, descLength);
        offset += 1;

        if (descLength > 0)
        {
            /* file description */
            gint end = descLength;
            char *desc = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
            proto_tree_add_string(part_root, hf_a615a_file_description, tvb, offset, descLength, desc);
            offset += descLength;
        }
    }
}

/* this routine dissects an LNR file */
static void
dissect_a615a_LNR(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree)
{
    gint end = -1;
    proto_tree *root = dissect_a615a_header(tvb, pinfo, &offset, tftp_tree, "Load Downloading Request", "LNR");

    /* file count */
    guint16 count = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_file_count, tvb, offset, 2, count);
    offset += 2;

    for (unsigned i = 0; i < count; i++)
    {
        /* file name length */
        gint fnameLengthOffset = offset;
        guint8 fnameLength = tvb_get_guint8(tvb, fnameLengthOffset);
        offset += 1;
        
        /* file name */
        gint fnameOffset = offset;
        end = fnameLength;
        char *fname = tvb_get_stringz_enc(wmem_packet_scope(), tvb, fnameOffset, &end, ENC_ASCII);
        offset += fnameLength;

        proto_tree *part_root;
        part_root = proto_tree_add_subtree_format(root, tvb, fnameLengthOffset, -1, ett_a615a_protocol_root, NULL, "Header %d - %s", i + 1, fname);

        proto_tree_add_uint(part_root, hf_a615a_file_name_length, tvb, fnameLengthOffset, 1, fnameLength);
        proto_tree_add_string(part_root, hf_a615a_file_name, tvb, fnameOffset, fnameLength, fname);
    }

    /* user data length */
    guint8 userDataLen = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_user_data_len, tvb, offset, 1, count);
    offset += 1;

    /* user data */
    proto_tree_add_item(root, hf_a615a_user_data, tvb, offset, userDataLen, ENC_NA);
}

/* this routine dissects an LNS file */
static void
dissect_a615a_LNS(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree)
{
    gint end;
    proto_tree *root = dissect_a615a_header(tvb, pinfo, &offset, tftp_tree, "Load Downloading Status", "LNS");

    /* download op status code */
    guint16 opCode = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_upload_op_status, tvb, offset, 2, opCode);
    offset += 2;

    /* status length */
    guint8 statLength = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_status_description_length, tvb, offset, 1, statLength);
    offset += 1;

    if (statLength > 0)
    {
        /* status description */
        end = statLength;
        char *statDesc = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
        proto_tree_add_string(root, hf_a615a_status_description, tvb, offset, statLength, statDesc);
        offset += statLength;
    }

    /* counter */
    guint16 counter = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_counter, tvb, offset, 2, counter);
    offset += 2;

    /* exception timer */
    guint16 excTimer = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_exception_timer, tvb, offset, 2, excTimer);
    offset += 2;

    /* estimated time */
    guint16 estTime = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_estimated_time, tvb, offset, 2, estTime);
    offset += 2;

    /* load list ratio */
    end = 3;
    char *llr = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
    proto_tree_add_string(root, hf_a615a_load_ratio, tvb, offset, 3, llr);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str(opCode, a615a_op_status_codes, "Unknown (0x%04x)"));
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Download Ratio: %s", llr);

    offset += 3;

    /* file count */
    guint16 count = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_file_count, tvb, offset, 2, count);
    offset += 2;

    for (unsigned i = 0; i < count; i++)
    {
        /* file name length */
        gint fnameLengthOffset = offset;
        guint8 fnameLength = tvb_get_guint8(tvb, fnameLengthOffset);
        offset += 1;
        
        /* file name */
        gint fnameOffset = offset;
        end = fnameLength;
        char *fname = tvb_get_stringz_enc(wmem_packet_scope(), tvb, fnameOffset, &end, ENC_ASCII);
        offset += fnameLength;

        proto_tree *part_root;
        part_root = proto_tree_add_subtree_format(root, tvb, fnameLengthOffset, -1, ett_a615a_protocol_root, NULL, "Header %d - %s", i + 1, fname);

        proto_tree_add_uint(part_root, hf_a615a_file_name_length, tvb, fnameLengthOffset, 1, fnameLength);
        proto_tree_add_string(part_root, hf_a615a_file_name, tvb, fnameOffset, fnameLength, fname);

        /* download op status code */
        guint16 opCode = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(root, hf_a615a_download_op_status, tvb, offset, 2, opCode);
        offset += 2;

        /* file description length */
        guint8 descLength = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(part_root, hf_a615a_file_description_length, tvb, offset, 1, descLength);
        offset += 1;

        if (descLength > 0)
        {
            /* file description */
            gint end = descLength;
            char *desc = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &end, ENC_ASCII);
            proto_tree_add_string(part_root, hf_a615a_file_description, tvb, offset, descLength, desc);
            offset += descLength;
        }
    }
}

/* this routine dissects an LNA file */
static void
dissect_a615a_LNA(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree)
{
    gint end = -1;
    proto_tree *root = dissect_a615a_header(tvb, pinfo, &offset, tftp_tree, "Load Downloading Answer", "LNR");

    /* file count */
    guint16 count = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(root, hf_a615a_file_count, tvb, offset, 2, count);
    offset += 2;

    for (unsigned i = 0; i < count; i++)
    {
        /* file name length */
        gint fnameLengthOffset = offset;
        guint8 fnameLength = tvb_get_guint8(tvb, fnameLengthOffset);
        offset += 1;
        
        /* file name */
        gint fnameOffset = offset;
        end = fnameLength;
        char *fname = tvb_get_stringz_enc(wmem_packet_scope(), tvb, fnameOffset, &end, ENC_ASCII);
        offset += fnameLength;

        proto_tree *part_root;
        part_root = proto_tree_add_subtree_format(root, tvb, fnameLengthOffset, -1, ett_a615a_protocol_root, NULL, "Header %d - %s", i + 1, fname);

        proto_tree_add_uint(part_root, hf_a615a_file_name_length, tvb, fnameLengthOffset, 1, fnameLength);
        proto_tree_add_string(part_root, hf_a615a_file_name, tvb, fnameOffset, fnameLength, fname);
    }
}

/* this routine provides a descriptive subtree for A665 file types */
static void
dissect_a615a_a665_msg(tvbuff_t *tvb, packet_info *pinfo, int offset, const char *a665Str, proto_tree *tftp_tree)
{
    (void)proto_tree_add_subtree_format(tftp_tree, tvb, offset, -1, ett_a665_protocol_root, NULL, "A665 %s File", a665Str);
}

/* this routien selects a dissection routine based on the file type to be dissected */
static void
dissect_a615a_protocol_file(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tftp_tree, int suffix)
{
    switch (suffix)
    {
        case LCI:
        {
            dissect_a615a_LCI(tvb, pinfo, offset, tftp_tree);
            break;
        }
        case LCL:
        {
            dissect_a615a_LCL(tvb, pinfo, offset, tftp_tree);
            break;
        }
        case LCS:
        {
            dissect_a615a_LCS(tvb, pinfo, offset, tftp_tree);
            break;
        }
        case LNA:
        {
            dissect_a615a_LNA(tvb, pinfo, offset, tftp_tree);
            break;
        }
        case LND:
        {
            dissect_a615a_LND(tvb, pinfo, offset, tftp_tree);
            break;
        }
        case LNL:
        {
            dissect_a615a_LNL(tvb, pinfo, offset, tftp_tree);
            break;
        }
        case LNO:
        {
            dissect_a615a_LNO(tvb, pinfo, offset, tftp_tree);
            break;
        }
        case LNR:
        {
            dissect_a615a_LNR(tvb, pinfo, offset, tftp_tree);
            break;
        }
        case LNS:
        {
            dissect_a615a_LNS(tvb, pinfo, offset, tftp_tree);
            break;
        }
        case LUI:
        {
            dissect_a615a_LUI(tvb, pinfo, offset, tftp_tree);
            break;
        }
        case LUR:
        {
            dissect_a615a_LUR(tvb, pinfo, offset, tftp_tree);
            break;
        }
        case LUS:
        {
            dissect_a615a_LUS(tvb, pinfo, offset, tftp_tree);
            break;
        }
        case LUB:
        {
            dissect_a615a_a665_msg(tvb, pinfo, offset, "Load Upload Batch (LUB)", tftp_tree);
            break;
        }
        case LUM:
        {
            dissect_a615a_a665_msg(tvb, pinfo, offset, "Load Upload Media (LUM)", tftp_tree);
            break;
        }
        case LUP:
        {
            dissect_a615a_a665_msg(tvb, pinfo, offset, "Load Upload Part (LUP, Data File)", tftp_tree);
            break;
        }
        case LUH:
        {
            dissect_a615a_a665_msg(tvb, pinfo, offset, "Load Upload Header (LUH)", tftp_tree);
            break;
        }
        default:
        {
            break;
        }
    }
}


static int
dissect_a615a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "A615a-3");
    //col_clear(pinfo->cinfo, COL_INFO);
    const char * filename = data;
    int suffix;
    for (suffix = LCI; suffix <= LUS; ++suffix) {
      const char *extension = a615a_file_ext[suffix];

      if (g_str_has_suffix(filename, extension)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s (%s)", filename,
                        extension);
        break;
      }
    }
    dissect_a615a_protocol_file(tvb, pinfo, 0, tree, suffix);

    return 0;
}

void proto_register_a615a(void)
{
    proto_a615a = proto_register_protocol(
        "Arinc 615a Protocol", /* name       */
        "A615a-3",               /* short name */
        "a615a"                /* abbrev     */
    );
    static hf_register_info hf[] = {
        /* A615a protocol fields */
        {&hf_a615a_file_length,
         {"File Length", "a615a.file_length", FT_UINT32, BASE_DEC, NULL, 0x0,
          "A615a Protocol File Length", HFILL}},
        {&hf_a615a_protocol_version,
         {"Protocol Version", "a615a.protocol_version", FT_STRINGZ, BASE_NONE,
          NULL, 0x0, "A615a Protocol File Version", HFILL}},
        {&hf_a615a_counter,
         {"Counter", "a615a.counter", FT_UINT16, BASE_DEC, NULL, 0x0,
          "A615a Protocol Counter", HFILL}},
        {&hf_a615a_info_op_status,
         {"Info Op Status Code", "a615a.info.status_code", FT_UINT16, BASE_DEC,
          VALS(a615a_op_status_codes), 0x0,
          "A615a Information Operation Status Code", HFILL}},
        {&hf_a615a_exception_timer,
         {"Exception Timer", "a615a.exception_timer", FT_UINT16, BASE_DEC, NULL,
          0x0, "A615a Exception Timer", HFILL}},
        {&hf_a615a_estimated_time,
         {"Estimated Time (seconds)", "a615a.estimated_time", FT_UINT16,
          BASE_DEC, NULL, 0x0, "A615a Estimated Time (Seconds)", HFILL}},
        {&hf_a615a_status_description_length,
         {"Status Length", "a615a.status.length", FT_UINT8, BASE_DEC, NULL, 0x0,
          "A615a Status Description Length", HFILL}},
        {&hf_a615a_status_description,
         {"Status Description", "a615a.status", FT_STRINGZ, BASE_NONE, NULL,
          0x0, "A615a Status Description", HFILL}},

        /* load list */
        {&hf_a615a_upload_op_status,
         {"Upload Op Status Code", "a615a.upload.status_code", FT_UINT16,
          BASE_DEC, VALS(a615a_op_status_codes), 0x0,
          "A615a Upload Operation Status Code", HFILL}},
        {&hf_a615a_download_op_status,
         {"Download Op Status Code", "a615a.download.status_code", FT_UINT16,
          BASE_DEC, VALS(a615a_op_status_codes), 0x0,
          "A615a Download Operation Status Code", HFILL}},

        /* load target */
        {&hf_a615a_part_load_op_status,
         {"Part Load Op Status Code", "a615a.upload.status_code", FT_UINT16,
          BASE_DEC, VALS(a615a_op_status_codes), 0x0,
          "A615a Part Load Op Status Code", HFILL}},
        {&hf_a615a_load_ratio,
         {"Load Ratio", "a615a.load_ratio", FT_STRINGZ, BASE_NONE, NULL, 0x0,
          "A615a Load Operation Ratio", HFILL}},
        {&hf_a615a_file_count,
         {"File Count", "a615a.file_count", FT_UINT16, BASE_DEC, NULL, 0x0,
          "A615a File Count", HFILL}},
        {&hf_a615a_file_name_length,
         {"File Name Length", "a615a.file_name.length", FT_UINT8, BASE_DEC,
          NULL, 0x0, "A615a File Name Length", HFILL}},
        {&hf_a615a_file_name,
         {"File Name", "a615a.file_name", FT_STRINGZ, BASE_NONE, NULL, 0x0,
          "A615a File Name", HFILL}},

        {&hf_a615a_file_description_length,
         {"File Description Length", "a615a.file_description.length", FT_UINT8,
          BASE_DEC, NULL, 0x0, "A615a File Description Length", HFILL}},
        {&hf_a615a_file_description,
         {"File Description", "a615a.file_description", FT_STRINGZ, BASE_NONE,
          NULL, 0x0, "A615a File Description", HFILL}},

        {&hf_a615a_part_number_length,
         {"Part Number Length", "a615a.part_number.length", FT_UINT8, BASE_DEC,
          NULL, 0x0, "A615a Part Number Length", HFILL}},
        {&hf_a615a_part_number,
         {"Part Number", "a615a.part_number", FT_STRINGZ, BASE_NONE, NULL, 0x0,
          "A615a Part Number", HFILL}},
        {&hf_a615a_tgt_hw_count,
         {"Number of Target Hardware", "a615a.num_hardware", FT_UINT16,
          BASE_DEC, NULL, 0x0, "A615a Number of Target Hardware", HFILL}},
        {&hf_a615a_lit_name_length,
         {"Literal Name Length", "a615a.literal_name.length", FT_UINT8,
          BASE_DEC, NULL, 0x0, "A615a Literal Name Length", HFILL}},
        {&hf_a615a_lit_name,
         {"Literal Name", "a615a.literal_name", FT_STRINGZ, BASE_NONE, NULL,
          0x0, "A615a Literal Name", HFILL}},
        {&hf_a615a_serial_num_length,
         {"Serial Number Length", "a615a.serial_number.length", FT_UINT8,
          BASE_DEC, NULL, 0x0, "A615a Serial Number Length", HFILL}},
        {&hf_a615a_serial_num,
         {"Serial Number", "a615a.serial_number", FT_STRINGZ, BASE_NONE, NULL,
          0x0, "A615a Serial Number", HFILL}},
        {&hf_a615a_part_num_count,
         {"Part Number Count", "a615a.num_parts", FT_UINT16, BASE_DEC, NULL,
          0x0, "A615a Part Number Count", HFILL}},
        {&hf_a615a_ammendment_len,
         {"Ammendment Length", "a615a.ammendment.length", FT_UINT8, BASE_DEC,
          NULL, 0x0, "A615a Ammendment Length", HFILL}},
        {&hf_a615a_ammendment,
         {"Ammendment", "a615a.ammendment", FT_STRINGZ, BASE_NONE, NULL, 0x0,
          "A615a Ammendment", HFILL}},
        {&hf_a615a_designation_len,
         {"Designation Length", "a615a.designation.length", FT_UINT8, BASE_DEC,
          NULL, 0x0, "A615a Designation Length", HFILL}},
        {&hf_a615a_designation,
         {"Designation", "a615a.designation", FT_STRINGZ, BASE_NONE, NULL, 0x0,
          "A615a Designation", HFILL}},
        {&hf_a615a_user_data_len,
         {"User Data Length", "a615a.user_data.length", FT_UINT8, BASE_DEC,
          NULL, 0x0, "User Data Length", HFILL}},
        {&hf_a615a_user_data,
         {"User Data", "a615a.user_data", FT_BYTES, BASE_NONE, NULL, 0x0,
          "User Data", HFILL}},
    };

    /* setup protocol subtree array */
    static gint *ett[] = {
        &ett_a615a,
        &ett_a615a_opt_root,
        &ett_a615a_opt,
        &ett_a615a_fragment,
        &ett_a615a_fragments,
        &ett_a615a_protocol_root,
        &ett_a665_protocol_root
    };

    proto_register_field_array(proto_a615a, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    fprintf(stderr, "ololo0\n");
}

static gboolean
dissect_a615a_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    // TODO сдесь проверку
    //fprintf(stderr, "ololo2 %d\n", (int)tvb_captured_length(tvb));
    //return (FALSE);

    /*   and do the dissection */
    dissect_a615a(tvb, pinfo, tree, data);
    
    return (TRUE);
}

void proto_reg_handoff_a615a(void)
{
	a615a_handle = create_dissector_handle(dissect_a615a, proto_a615a);
    //dissector_add_uint_range_with_preference("udp.port", "59", a615a_handle);
	//dissector_add_string("tftp.source_file", "SXTCPIOM-K_01.LCI", a615a_handle);
    heur_dissector_add("tftp2", dissect_a615a_heur, "22 Arinc 615a Protocol", "22 A615a-3", proto_a615a, HEURISTIC_ENABLE);
    fprintf(stderr, "ololo1\n");
}