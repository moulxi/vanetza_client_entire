/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "AVIAEINumberingAndDataStructures"
 * 	found in "build.asn1/iso/ISO14816.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_ServiceNumber_H_
#define	_ServiceNumber_H_


#include "asn_application.h"

/* Including external dependencies */
#include "BIT_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ServiceNumber */
typedef BIT_STRING_t	 ServiceNumber_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_ServiceNumber_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_ServiceNumber;
asn_struct_free_f ServiceNumber_free;
asn_struct_print_f ServiceNumber_print;
asn_constr_check_f ServiceNumber_constraint;
ber_type_decoder_f ServiceNumber_decode_ber;
der_type_encoder_f ServiceNumber_encode_der;
xer_type_decoder_f ServiceNumber_decode_xer;
xer_type_encoder_f ServiceNumber_encode_xer;
oer_type_decoder_f ServiceNumber_decode_oer;
oer_type_encoder_f ServiceNumber_encode_oer;
per_type_decoder_f ServiceNumber_decode_uper;
per_type_encoder_f ServiceNumber_encode_uper;
per_type_decoder_f ServiceNumber_decode_aper;
per_type_encoder_f ServiceNumber_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _ServiceNumber_H_ */
#include "asn_internal.h"
