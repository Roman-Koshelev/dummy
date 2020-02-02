#include <stdio.h>

#include <config.h>

#include <epan/packet.h>

#define PARS_RET_UINT8(proto_tree, name)                                                      \
    guint32 name;                                                                             \
    proto_tree_add_item_ret_uint(proto_tree, hf_a615a_##name, tvb, offset, 1, ENC_NA, &name); \
    offset += 1

#define PARS_RET_UINT16(proto_tree, name)                                                     \
    guint32 name;                                                                             \
    proto_tree_add_item_ret_uint(proto_tree, hf_a615a_##name, tvb, offset, 2, ENC_BIG_ENDIAN, \
                                 &name);                                                      \
    offset += 2

#define PARS_UINT16(proto_tree, name)                                                 \
    proto_tree_add_item(proto_tree, hf_a615a_##name, tvb, offset, 2, ENC_BIG_ENDIAN); \
    offset += 2

#define PARS_UINT32(proto_tree, name)                                                 \
    proto_tree_add_item(proto_tree, hf_a615a_##name, tvb, offset, 4, ENC_BIG_ENDIAN); \
    offset += 4

#define PARS_OPERATION_STATUS_CODE(proto_tree, name)                                         \
    do {                                                                                     \
        PARS_RET_UINT16(proto_tree, name);                                                   \
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s",                              \
                        val_to_str(name, a615a_operation_status_codes, "Unknown (0x%04x)")); \
    } while (0);

#define PARS_STRING(proto_tree, name)                                                        \
    proto_tree_add_item(proto_tree, hf_a615a_##name, tvb, offset, name##_length, ENC_ASCII); \
    offset += name##_length

#define PARS_LOAD_RATIO(proto_tree)                                                  \
    proto_tree_add_item(proto_tree, hf_a615a_load_ratio, tvb, offset, 3, ENC_ASCII); \
    offset += 3

#define PARS_A615STRING_LENGTH(proto_tree, name) PARS_RET_UINT8(proto_tree, name##_length)

#define PARS_A615STRING(proto_tree, name)         \
    do {                                          \
        PARS_A615STRING_LENGTH(proto_tree, name); \
        if (name##_length > 0) {                  \
            PARS_STRING(proto_tree, name);        \
        }                                         \
    } while (0)

enum A615A_SUFFIX { LCI, LCL, LCS, LNA, LND, LNL, LNO, LNR, LNS, LUI, LUR, LUS };

typedef struct _string_pair {
    const char *abbreviated;
    const char *full;
} string_pair;

static string_pair a615a_file[] = {{"LCI", "Load Configuration Initialization"},
                                   {"LCL", "Load Configuration List"},
                                   {"LCS", "Load Configuration Status"},
                                   {"LNA", "Load Downloading Answer"},
                                   {"LND", "Load Downloading Media"},
                                   {"LNL", "Load Downloading List"},
                                   {"LNO", "Load Downloading Operator"},
                                   {"LNR", "Load Downloading Request"},
                                   {"LNS", "Load Downloading Status"},
                                   {"LUI", "Load Upload Initialization"},
                                   {"LUR", "Load Uploading Request"},
                                   {"LUS", "Load Uploading Status"}};

static const value_string a615a_operation_status_codes[] = {
    {0x0001, "Accepted, not yet started"},
    {0x0002, "Operation in progress"},
    {0x0003, "Operation completed without error"},
    {0x0004, "Operation in progress, details in status description"},
    {0x1000, "Operation denied, reason in status description"},
    {0x1002, "Operation not supported by the target"},
    {0x1003, "Operation aborted by target hardware, info in status description"},
    {0x1004, "Operation aborted by target on Dataloader error message"},
    {0x1005, "Operation aborted by target on operator action"},
    {0x1007, "Load of this header file has failed, details in status description"},
    {0, NULL}};

static int proto_a615a = -1;
dissector_handle_t a615a_handle;

static gint ett_a615a_protocol_root = -1;

static int hf_a615a_file_length = -1;
static int hf_a615a_protocol_version = -1;
static int hf_a615a_counter = -1;
static int hf_a615a_info_operation_status = -1;
static int hf_a615a_upload_operation_status = -1;
static int hf_a615a_download_operation_status = -1;
static int hf_a615a_part_load_operation_status = -1;
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
static int hf_a615a_number_target_hardware = -1;
static int hf_a615a_literal_name_length = -1;
static int hf_a615a_literal_name = -1;
static int hf_a615a_serial_number_length = -1;
static int hf_a615a_serial_number = -1;
static int hf_a615a_part_number_count = -1;
static int hf_a615a_ammendment_length = -1;
static int hf_a615a_ammendment = -1;
static int hf_a615a_designation_length = -1;
static int hf_a615a_designation = -1;
static int hf_a615a_user_data_length = -1;
static int hf_a615a_user_data = -1;

static void dissect_a615a_LCL(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_RET_UINT16(root, number_target_hardware);

    for (unsigned i = 0; i < number_target_hardware; ++i) {
        PARS_A615STRING(root, literal_name);
        PARS_A615STRING(root, serial_number);

        PARS_RET_UINT16(root, part_number_count);

        for (unsigned i = 0; i < part_number_count; ++i) {
            int len = tvb_get_guint8(tvb, offset);
            char *str = tvb_format_text(tvb, offset + 1, len - 1);
            proto_tree *part_root = proto_tree_add_subtree_format(
                root, tvb, offset, -1, ett_a615a_protocol_root, NULL, "Part %d - %s", i + 1, str);

            int begin_offset = offset;
            PARS_A615STRING(part_root, part_number);
            PARS_A615STRING(part_root, ammendment);
            PARS_A615STRING(part_root, designation);
            proto_item_set_len(part_root, offset - begin_offset);
        }
    }
}

static void dissect_a615a_LUS(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_OPERATION_STATUS_CODE(root, upload_operation_status);
    PARS_A615STRING(root, status_description);
    PARS_UINT16(root, counter);
    PARS_UINT16(root, exception_timer);
    PARS_UINT16(root, estimated_time);
    PARS_LOAD_RATIO(root);
    PARS_RET_UINT16(root, file_count);

    for (unsigned i = 0; i < file_count; ++i) {
        int len = tvb_get_guint8(tvb, offset);
        char *str = tvb_format_text(tvb, offset + 1, len - 1);
        proto_tree *part_root = proto_tree_add_subtree_format(
            root, tvb, offset, -1, ett_a615a_protocol_root, NULL, "Header %d - %s", i + 1, str);

        int begin_offset = offset;
        PARS_A615STRING(part_root, file_name);
        PARS_A615STRING(part_root, part_number);
        PARS_LOAD_RATIO(part_root);
        PARS_UINT16(part_root, part_load_operation_status);
        PARS_A615STRING(part_root, status_description);
        proto_item_set_len(part_root, offset - begin_offset);
    }
}

static void dissect_a615a_LCS(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_UINT16(root, counter);
    PARS_OPERATION_STATUS_CODE(root, info_operation_status);
    PARS_UINT16(root, exception_timer);
    PARS_UINT16(root, estimated_time);
    PARS_A615STRING(root, status_description);
}

static void dissect_a615a_LUI(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_OPERATION_STATUS_CODE(root, upload_operation_status);
    PARS_A615STRING(root, status_description);
}

static void dissect_a615a_LCI(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_OPERATION_STATUS_CODE(root, info_operation_status);
    PARS_A615STRING(root, status_description);
}

static void dissect_a615a_LND(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_OPERATION_STATUS_CODE(root, download_operation_status);
    PARS_A615STRING(root, status_description);
}

static void dissect_a615a_LNO(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_OPERATION_STATUS_CODE(root, download_operation_status);
    PARS_A615STRING(root, status_description);
}

static void dissect_a615a_LUR(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_RET_UINT16(root, file_count);

    for (unsigned i = 0; i < file_count; ++i) {
        int len = tvb_get_guint8(tvb, offset);
        char *str = tvb_format_text(tvb, offset + 1, len - 1);
        proto_tree *part_root = proto_tree_add_subtree_format(
            root, tvb, offset, -1, ett_a615a_protocol_root, NULL, "Header %d - %s", i + 1, str);

        int begin_offset = offset;
        PARS_A615STRING(part_root, file_name);
        PARS_A615STRING(part_root, part_number);
        proto_item_set_len(part_root, offset - begin_offset);
    }
}

static void dissect_a615a_LNL(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_RET_UINT16(root, file_count);

    for (unsigned i = 0; i < file_count; ++i) {
        int len = tvb_get_guint8(tvb, offset);
        char *str = tvb_format_text(tvb, offset + 1, len - 1);

        proto_tree *part_root = proto_tree_add_subtree_format(
            root, tvb, offset, -1, ett_a615a_protocol_root, NULL, "Header %d - %s", i + 1, str);

        int begin_offset = offset;
        PARS_A615STRING(part_root, file_name);
        PARS_A615STRING(part_root, file_description);
        proto_item_set_len(part_root, offset - begin_offset);
    }
}

static void dissect_a615a_LNR(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_RET_UINT16(root, file_count);

    for (unsigned i = 0; i < file_count; ++i) {
        int len = tvb_get_guint8(tvb, offset);
        char *str = tvb_format_text(tvb, offset + 1, len - 1);
        proto_tree *part_root = proto_tree_add_subtree_format(
            root, tvb, offset, -1, ett_a615a_protocol_root, NULL, "Header %d - %s", i + 1, str);

        int begin_offset = offset;
        PARS_A615STRING(part_root, file_name);
        proto_item_set_len(part_root, offset - begin_offset);
    }

    PARS_RET_UINT8(root, user_data_length);
    if (user_data_length > 0) {
        proto_tree_add_item(root, hf_a615a_user_data, tvb, offset, user_data_length, ENC_NA);
    }
}

static void dissect_a615a_LNS(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_OPERATION_STATUS_CODE(root, download_operation_status);
    PARS_A615STRING(root, status_description);
    PARS_UINT16(root, counter);
    PARS_UINT16(root, exception_timer);
    PARS_UINT16(root, estimated_time);
    PARS_LOAD_RATIO(root);
    PARS_RET_UINT16(root, file_count);

    for (unsigned i = 0; i < file_count; ++i) {
        int len = tvb_get_guint8(tvb, offset);
        char *str = tvb_format_text(tvb, offset + 1, len - 1);

        proto_tree *part_root = proto_tree_add_subtree_format(
            root, tvb, offset, -1, ett_a615a_protocol_root, NULL, "Header %d - %s", i + 1, str);

        int begin_offset = offset;
        PARS_A615STRING(part_root, file_name);
        PARS_UINT16(part_root, download_operation_status);
        PARS_A615STRING(part_root, file_description);
        proto_item_set_len(part_root, offset - begin_offset);
    }
}

static void dissect_a615a_LNA(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_RET_UINT16(root, file_count);

    for (unsigned i = 0; i < file_count; ++i) {
        int len = tvb_get_guint8(tvb, offset);
        char *str = tvb_format_text(tvb, offset + 1, len - 1);
        proto_tree *part_root = proto_tree_add_subtree_format(
            root, tvb, offset, -1, ett_a615a_protocol_root, NULL, "Header %d - %s", i + 1, str);

        int begin_offset = offset;
        PARS_A615STRING(part_root, file_name);
        proto_item_set_len(part_root, offset - begin_offset);
    }
}

static void dissect_a615a_protocol_file(tvbuff_t *tvb, packet_info *pinfo, int offset,
                                        proto_tree *tftp_tree, int suffix)
{
    proto_tree *a615a_tree = proto_tree_add_subtree_format(
        tftp_tree, tvb, offset, -1, ett_a615a_protocol_root, NULL, "%s (%s)",
        a615a_file[suffix].full, a615a_file[suffix].abbreviated);
    PARS_UINT32(a615a_tree, file_length);
    proto_tree_add_item(a615a_tree, hf_a615a_protocol_version, tvb, offset, 2, ENC_ASCII);
    offset += 2;

    switch (suffix) {
        case LCI: {
            dissect_a615a_LCI(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LCL: {
            dissect_a615a_LCL(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LCS: {
            dissect_a615a_LCS(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LNA: {
            dissect_a615a_LNA(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LND: {
            dissect_a615a_LND(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LNL: {
            dissect_a615a_LNL(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LNO: {
            dissect_a615a_LNO(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LNR: {
            dissect_a615a_LNR(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LNS: {
            dissect_a615a_LNS(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LUI: {
            dissect_a615a_LUI(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LUR: {
            dissect_a615a_LUR(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LUS: {
            dissect_a615a_LUS(tvb, pinfo, offset, a615a_tree);
            break;
        }
        default: {
            DISSECTOR_ASSERT_NOT_REACHED();
            break;
        }
    }
}

struct tftpinfo {
    const char *filename;
};

static int dissect_a615a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return 0;
}

static gboolean dissect_a615a_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    guint psize = tvb_captured_length(tvb);
    if (psize < 6) return FALSE;
    if ((tvb_get_ntohl(tvb, 0) != psize) || ((gchar)tvb_get_guint8(tvb, 5) != 'A')) return FALSE;

    const char *filename = ((struct tftpinfo *)data)->filename;
    for (int i = 0; i < (sizeof(a615a_file) / sizeof(string_pair)); ++i) {
        const char *extension = a615a_file[i].abbreviated;
        if (g_str_has_suffix(filename, extension)) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "A615a-3");
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", filename);
            dissect_a615a_protocol_file(tvb, pinfo, 0, tree, i);
            return TRUE;
        }
    }
    return FALSE;
}

void proto_register_a615a(void)
{
    static hf_register_info hf[] = {
        {&hf_a615a_file_length,
         {"File Length", "a615a.file_length", FT_UINT32, BASE_DEC, NULL, 0x0,
          "A615a Protocol File Length", HFILL}},
        {&hf_a615a_protocol_version,
         {"Protocol Version", "a615a.protocol_version", FT_STRINGZ, BASE_NONE, NULL, 0x0,
          "A615a Protocol File Version", HFILL}},
        {&hf_a615a_counter,
         {"Counter", "a615a.counter", FT_UINT16, BASE_DEC, NULL, 0x0, "A615a Protocol Counter",
          HFILL}},
        {&hf_a615a_info_operation_status,
         {"Info Operation Status Code", "a615a.info.status_code", FT_UINT16, BASE_DEC,
          VALS(a615a_operation_status_codes), 0x0, "A615a Information Operation Status Code",
          HFILL}},
        {&hf_a615a_exception_timer,
         {"Exception Timer", "a615a.exception_timer", FT_UINT16, BASE_DEC, NULL, 0x0,
          "A615a Exception Timer", HFILL}},
        {&hf_a615a_estimated_time,
         {"Estimated Time (seconds)", "a615a.estimated_time", FT_UINT16, BASE_DEC, NULL, 0x0,
          "A615a Estimated Time (Seconds)", HFILL}},
        {&hf_a615a_status_description_length,
         {"Status Length", "a615a.status.length", FT_UINT8, BASE_DEC, NULL, 0x0,
          "A615a Status Description Length", HFILL}},
        {&hf_a615a_status_description,
         {"Status Description", "a615a.status", FT_STRINGZ, BASE_NONE, NULL, 0x0,
          "A615a Status Description", HFILL}},
        {&hf_a615a_upload_operation_status,
         {"Upload Operation Status Code", "a615a.upload.status_code", FT_UINT16, BASE_DEC,
          VALS(a615a_operation_status_codes), 0x0, "A615a Upload Operation Status Code", HFILL}},
        {&hf_a615a_download_operation_status,
         {"Download Operation Status Code", "a615a.download.status_code", FT_UINT16, BASE_DEC,
          VALS(a615a_operation_status_codes), 0x0, "A615a Download Operation Status Code", HFILL}},
        {&hf_a615a_part_load_operation_status,
         {"Part Load Operation Status Code", "a615a.upload.status_code", FT_UINT16, BASE_DEC,
          VALS(a615a_operation_status_codes), 0x0, "A615a Part Load Operation Status Code", HFILL}},
        {&hf_a615a_load_ratio,
         {"Load Ratio", "a615a.load_ratio", FT_STRINGZ, BASE_NONE, NULL, 0x0,
          "A615a Load Operation Ratio", HFILL}},
        {&hf_a615a_file_count,
         {"File Count", "a615a.file_count", FT_UINT16, BASE_DEC, NULL, 0x0, "A615a File Count",
          HFILL}},
        {&hf_a615a_file_name_length,
         {"File Name Length", "a615a.file_name.length", FT_UINT8, BASE_DEC, NULL, 0x0,
          "A615a File Name Length", HFILL}},
        {&hf_a615a_file_name,
         {"File Name", "a615a.file_name", FT_STRINGZ, BASE_NONE, NULL, 0x0, "A615a File Name",
          HFILL}},
        {&hf_a615a_file_description_length,
         {"File Description Length", "a615a.file_description.length", FT_UINT8, BASE_DEC, NULL, 0x0,
          "A615a File Description Length", HFILL}},
        {&hf_a615a_file_description,
         {"File Description", "a615a.file_description", FT_STRINGZ, BASE_NONE, NULL, 0x0,
          "A615a File Description", HFILL}},
        {&hf_a615a_part_number_length,
         {"Part Number Length", "a615a.part_number.length", FT_UINT8, BASE_DEC, NULL, 0x0,
          "A615a Part Number Length", HFILL}},
        {&hf_a615a_part_number,
         {"Part Number", "a615a.part_number", FT_STRINGZ, BASE_NONE, NULL, 0x0, "A615a Part Number",
          HFILL}},
        {&hf_a615a_number_target_hardware,
         {"Number of Target Hardware", "a615a.num_hardware", FT_UINT16, BASE_DEC, NULL, 0x0,
          "A615a Number of Target Hardware", HFILL}},
        {&hf_a615a_literal_name_length,
         {"Literal Name Length", "a615a.literal_name.length", FT_UINT8, BASE_DEC, NULL, 0x0,
          "A615a Literal Name Length", HFILL}},
        {&hf_a615a_literal_name,
         {"Literal Name", "a615a.literal_name", FT_STRINGZ, BASE_NONE, NULL, 0x0,
          "A615a Literal Name", HFILL}},
        {&hf_a615a_serial_number_length,
         {"Serial Number Length", "a615a.serial_number.length", FT_UINT8, BASE_DEC, NULL, 0x0,
          "A615a Serial Number Length", HFILL}},
        {&hf_a615a_serial_number,
         {"Serial Number", "a615a.serial_number", FT_STRINGZ, BASE_NONE, NULL, 0x0,
          "A615a Serial Number", HFILL}},
        {&hf_a615a_part_number_count,
         {"Part Number Count", "a615a.num_parts", FT_UINT16, BASE_DEC, NULL, 0x0,
          "A615a Part Number Count", HFILL}},
        {&hf_a615a_ammendment_length,
         {"Ammendment Length", "a615a.ammendment.length", FT_UINT8, BASE_DEC, NULL, 0x0,
          "A615a Ammendment Length", HFILL}},
        {&hf_a615a_ammendment,
         {"Ammendment", "a615a.ammendment", FT_STRINGZ, BASE_NONE, NULL, 0x0, "A615a Ammendment",
          HFILL}},
        {&hf_a615a_designation_length,
         {"Designation Length", "a615a.designation.length", FT_UINT8, BASE_DEC, NULL, 0x0,
          "A615a Designation Length", HFILL}},
        {&hf_a615a_designation,
         {"Designation", "a615a.designation", FT_STRINGZ, BASE_NONE, NULL, 0x0, "A615a Designation",
          HFILL}},
        {&hf_a615a_user_data_length,
         {"User Data Length", "a615a.user_data.length", FT_UINT8, BASE_DEC, NULL, 0x0,
          "User Data Length", HFILL}},
        {&hf_a615a_user_data,
         {"User Data", "a615a.user_data", FT_BYTES, BASE_NONE, NULL, 0x0, "User Data", HFILL}},
    };

    static gint *ett[] = {&ett_a615a_protocol_root};

    proto_a615a = proto_register_protocol("Arinc 615a Protocol", "A615a-3", "a615a");
    proto_register_field_array(proto_a615a, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    a615a_handle = create_dissector_handle(dissect_a615a, proto_a615a);
}

void proto_reg_handoff_a615a(void)
{
    heur_dissector_add("tftp", dissect_a615a_heur, "Arinc 615a Protocol", "a615a-3", proto_a615a,
                       HEURISTIC_ENABLE);
}