/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "CPM-PDU-Descriptions"
 * 	found in "asn1/TR103562v211-CPM.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_SpeedExtended_H_
#define	_SpeedExtended_H_


#include "asn_application.h"

/* Including external dependencies */
#include "SpeedValueExtended.h"
#include "SpeedConfidence.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SpeedExtended */
typedef struct SpeedExtended {
	SpeedValueExtended_t	 value;
	SpeedConfidence_t	 confidence;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SpeedExtended_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SpeedExtended;
extern asn_SEQUENCE_specifics_t asn_SPC_SpeedExtended_specs_1;
extern asn_TYPE_member_t asn_MBR_SpeedExtended_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _SpeedExtended_H_ */
#include "asn_internal.h"
