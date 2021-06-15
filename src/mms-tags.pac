enum protocol_tags
{
	SPDU_DATA               = 1,
	SPDU_CONNECT            = 13,
	SPDU_ACCEPT             = 14,

	TPDU_CR                 = 0xd0,
	TPDU_CC                 = 0xe0,
	TPDU_DT                 = 0xf0,

	PRES_CONNECT            = 0x31,
	PRES_DATA               = 0x61,

	MMS_CONFIRMED_REQ_PDU   = 0xa0,
	MMS_CONFIRMED_RES_PDU   = 0xa1,
	MMS_CONFIRMED_ERROR_PDU = 0xa2,
	MMS_INITIATE_REQ_PDU    = 0xa8,
	MMS_INITIATE_RES_PDU    = 0xa9,

	MMS_CANCEL_REQ_PDU      = 0x85,
	MMS_CANCEL_RES_PDU      = 0x86,
	MMS_CONCLUDE_REQ_PDU    = 0x8b,
	MMS_CONCLUDE_RES_PDU    = 0x8c,
	MMS_CONCLUDE_ERR_PDU    = 0xad,

	MMS_SERVICE_REQ_STATUS                          = 0x80,
	MMS_SERVICE_REQ_GET_NAME_LIST                   = 0xa1,
	MMS_SERVICE_REQ_IDENTIFY                        = 0x82,
	MMS_SERVICE_REQ_RENAME                          = 0xa3,
	MMS_SERVICE_REQ_READ                            = 0xa4,
	MMS_SERVICE_REQ_WRITE                           = 0xa5,
	MMS_SERVICE_REQ_GET_VAR_ACCESS_ATTR             = 0xa6,
	MMS_SERVICE_REQ_DEFINE_NAMED_VAR                = 0xa7,
	MMS_SERVICE_REQ_DEFINE_NAMED_VAR_LIST           = 0xab,
	MMS_SERVICE_REQ_GET_NAMED_VAR_LIST_ATTR         = 0xac,
	MMS_SERVICE_REQ_DELETE_NAMED_VAR_LIST           = 0xad,
	MMS_SERVICE_REQ_OBTAIN_FILE                     = 0x2e,
	MMS_SERVICE_REQ_READ_JOURNAL                    = 0x41,
	MMS_SERVICE_REQ_FILE_OPEN                       = 0x48,
	MMS_SERVICE_REQ_FILE_READ                       = 0x49,
	MMS_SERVICE_REQ_FILE_CLOSE                      = 0x4a,
	MMS_SERVICE_REQ_FILE_RENAME                     = 0x4b,
	MMS_SERVICE_REQ_FILE_DELETE                     = 0x4c,
	MMS_SERVICE_REQ_FILE_DIRECTORY                  = 0x4d,

	MMS_SERVICE_RES_STATUS                          = 0xa0,
	MMS_SERVICE_RES_GET_NAME_LIST                   = 0xa1,
	MMS_SERVICE_RES_IDENTIFY                        = 0xa2,
	MMS_SERVICE_RES_RENAME                          = 0xa3,
	MMS_SERVICE_RES_READ                            = 0xa4,
	MMS_SERVICE_RES_WRITE                           = 0xa5,
	MMS_SERVICE_RES_GET_VAR_ACCESS_ATTR             = 0xa6,
	MMS_SERVICE_RES_DEFINE_NAMED_VAR                = 0xa7,
	MMS_SERVICE_RES_DEFINE_NAMED_VAR_LIST           = 0x8b,
	MMS_SERVICE_RES_GET_NAMED_VAR_LIST_ATTR         = 0xac,
	MMS_SERVICE_RES_DELETE_NAMED_VAR_LIST           = 0xad,
	MMS_SERVICE_RES_OBTAIN_FILE                     = 0x2e,
	MMS_SERVICE_RES_READ_JOURNAL                    = 0x41,
	MMS_SERVICE_RES_FILE_OPEN                       = 0x48,
	MMS_SERVICE_RES_FILE_READ                       = 0x49,
	MMS_SERVICE_RES_FILE_CLOSE                      = 0x4a,
	MMS_SERVICE_RES_FILE_RENAME                     = 0x4b,
	MMS_SERVICE_RES_FILE_DELETE                     = 0x4c,
	MMS_SERVICE_RES_FILE_DIRECTORY                  = 0x4d,


	BASIC_OBJECT_CLASS      = 0x80,
	CS_OBJECT_CLASS         = 0x81,

	DOMAIN                  = 0x09,
	NAMED_VARIABLE          = 0x00,

	VMD_SPECIFIC            = 0x80,
	DOMAIN_SPECIFIC         = 0x81,
	AA_SPECIFIC             = 0x82,
	
	# Datatypes must be positive tags as they are passed to script as Count.
	DATATYPE_ARRAY              = 0xa0,
	DATATYPE_STRUCTURE          = 0xa2,
	DATATYPE_BOOLEAN            = 0x83,
	DATATYPE_BIT_STRING         = 0x84,
	DATATYPE_INTEGER            = 0x85,
	DATATYPE_UNSIGNED           = 0x86,
	DATATYPE_FLOATING_POINT     = 0x87,
	DATATYPE_OCTET_STRING       = 0x89,
	DATATYPE_VISIBLE_STRING     = 0x8a,
	DATATYPE_GENERALIZED_TIME   = 0x8b,
	DATATYPE_BINARY_TIME        = 0x8c,
	DATATYPE_BCD                = 0x8d,
	DATATYPE_BOOLEAN_ARRAY      = 0x8e,
	DATATYPE_OBJID              = 0x8f,
	DATATYPE_MMS_STRING         = 0x90,
	DATATYPE_UTC_TIME           = 0x91,
	DATATYPE_GRAPHIC_STRING     = 0x19,

	UNIVERSAL_SEQUENCE          = 0x30,

	DATAACCESSERROR_OBJECT_INVALIDATED              = 0,
	DATAACCESSERROR_HARDWARE_FAULT                  = 1,
	DATAACCESSERROR_TEMPORARILY_UNAVAILABLE         = 2,
	DATAACCESSERROR_OBJECT_ACCESS_DENIED            = 3,
	DATAACCESSERROR_OBJECT_UNDEFINED                = 4,
	DATAACCESSERROR_INVALID_ADDRESS                 = 5,
	DATAACCESSERROR_TYPE_UNSUPPORTED                = 6,
	DATAACCESSERROR_TYPE_INCONSISTENT               = 7,
	DATAACCESSERROR_OBJECT_ATTRIBUTE_INCOSISTENT    = 8,
	DATAACCESSERROR_OBJECT_ACCESS_UNSUPPORTED       = 9,
	DATAACCESSERROR_OBJECT_NON_EXISTENT             = 10,
	DATAACCESSERROR_OBJECT_VALUE_INVALID            = 11,

	STATE_CHANGES_ALLOWED       = 0,
	NO_STATE_CHANGES_ALLOWED    = 1,
	LIMITED_SERVICES_PERMITTED  = 2,
	SUPPORT_SERVICES_ALLOWED    = 3,

	OPERATIONAL             = 0,
	PARTIALLY_OPERATIONAL   = 1,
	INOPERABLE              = 2,
	NEEDS_COMMISSIONING     = 3,
};

# Requests and responses cannot be differentiated by service codes alone
enum internal_service_codes
{
	BIF_MMS_SERVICE_REQ_GET_NAME_LIST           = 000,
	BIF_MMS_SERVICE_REQ_READ                    = 001,
	BIF_MMS_SERVICE_REQ_WRITE                   = 002,
	BIF_MMS_SERVICE_REQ_GET_VAR_ACCESS_ATTR     = 003,
	BIF_MMS_SERVICE_REQ_GET_NAMED_VAR_LIST_ATTR = 004,
	BIF_MMS_SERVICE_REQ_STATUS                  = 005,
	BIF_MMS_CONCLUDE_REQ_PDU                    = 006,
	BIF_MMS_SERVICE_REQ_FILE_DIRECTORY          = 007,
	BIF_MMS_SERVICE_REQ_FILE_OPEN               = 008,
	BIF_MMS_SERVICE_REQ_FILE_READ               = 009,
	BIF_MMS_SERVICE_REQ_FILE_CLOSE              = 010,
	BIF_MMS_SERVICE_REQ_IDENTIFY                = 011,
	BIF_MMS_SERVICE_REQ_FILE_RENAME             = 012,
	BIF_MMS_SERVICE_REQ_DEFINE_NAMED_VAR_LIST   = 013,
	BIF_MMS_SERVICE_REQ_DELETE_NAMED_VAR_LIST   = 014,
	BIF_MMS_INITIATE_REQ_PDU                    = 015,
	BIF_MMS_SERVICE_REQ_OBTAIN_FILE             = 016,
	BIF_MMS_CANCEL_REQ_PDU                      = 017,
	
	BIF_MMS_SERVICE_RES_GET_NAME_LIST           = 100,
	BIF_MMS_SERVICE_RES_READ                    = 101,
	BIF_MMS_SERVICE_RES_WRITE                   = 102,
	BIF_MMS_SERVICE_RES_GET_VAR_ACCESS_ATTR     = 103,
	BIF_MMS_SERVICE_RES_GET_NAMED_VAR_LIST_ATTR = 104,
	BIF_MMS_SERVICE_RES_STATUS                  = 105,
	BIF_MMS_CONCLUDE_RES_PDU                    = 106,
	BIF_MMS_SERVICE_RES_FILE_DIRECTORY          = 107,
	BIF_MMS_SERVICE_RES_FILE_OPEN               = 108,
	BIF_MMS_SERVICE_RES_FILE_READ               = 109,
	BIF_MMS_SERVICE_RES_FILE_CLOSE              = 110,
	BIF_MMS_SERVICE_RES_IDENTIFY                = 111,
	BIF_MMS_SERVICE_RES_FILE_RENAME             = 112,
	BIF_MMS_SERVICE_RES_DEFINE_NAMED_VAR_LIST   = 113,
	BIF_MMS_SERVICE_RES_DELETE_NAMED_VAR_LIST   = 114,
	BIF_MMS_INITIATE_RES_PDU                    = 115,
	BIF_MMS_SERVICE_RES_OBTAIN_FILE             = 116,
	BIF_MMS_CANCEL_RES_PDU                      = 117,
};