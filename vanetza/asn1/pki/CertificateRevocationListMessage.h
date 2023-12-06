/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EtsiTs102941MessagesCa"
 * 	found in "asn1/TS102941v131-MessagesCa.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_CertificateRevocationListMessage_H_
#define	_CertificateRevocationListMessage_H_


#include "asn_application.h"

/* Including external dependencies */
#include "EtsiTs103097Data-Signed.h"

#ifdef __cplusplus
extern "C" {
#endif

/* CertificateRevocationListMessage */
typedef EtsiTs103097Data_Signed_55P0_t	 CertificateRevocationListMessage_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CertificateRevocationListMessage;
asn_struct_free_f CertificateRevocationListMessage_free;
asn_struct_print_f CertificateRevocationListMessage_print;
asn_constr_check_f CertificateRevocationListMessage_constraint;
ber_type_decoder_f CertificateRevocationListMessage_decode_ber;
der_type_encoder_f CertificateRevocationListMessage_encode_der;
xer_type_decoder_f CertificateRevocationListMessage_decode_xer;
xer_type_encoder_f CertificateRevocationListMessage_encode_xer;
oer_type_decoder_f CertificateRevocationListMessage_decode_oer;
oer_type_encoder_f CertificateRevocationListMessage_encode_oer;
per_type_decoder_f CertificateRevocationListMessage_decode_uper;
per_type_encoder_f CertificateRevocationListMessage_encode_uper;
per_type_decoder_f CertificateRevocationListMessage_decode_aper;
per_type_encoder_f CertificateRevocationListMessage_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _CertificateRevocationListMessage_H_ */
#include "asn_internal.h"
