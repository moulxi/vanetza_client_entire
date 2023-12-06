#ifndef ISSUER_HPP_9K6GXK4R
#define ISSUER_HPP_9K6GXK4R

#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/public_key.hpp>
#include <boost/variant/recursive_wrapper.hpp>
#include <boost/variant/variant.hpp>
#include <cstddef>
#include <cstdint>
#include <list>

namespace vanetza
{
    namespace security
    {

        struct Certificate;

        /// described in TS 103 097 v1.2.1, section 4.2.11
        enum class IssuerType : uint8_t
        {
            Self = 0,                                   // nothing -> nullptr_t
            Certificate_Digest_With_SHA256 = 1,         // HashedId8
            Certificate = 2,                            // Certificate
            Certificate_Chain = 3,                      // std::list<Certificate>
            Certificate_Digest_With_Other_Algorithm = 4 // CertificateDigestWithOtherAlgorithm
        };
        struct CertificateDigestWithOtherAlgorithm
        {
            PublicKeyAlgorithm algorithm;
            HashedId8 digest;
        };
        /// described in TS 103 097 v1.2.1, section 4.2.10
        using Issuer = boost::variant<
            std::nullptr_t,
            HashedId8,
            boost::recursive_wrapper<Certificate>,
            std::list<Certificate>,
            CertificateDigestWithOtherAlgorithm>;

        /**
         * \brief Determines SignerInfoType of SignerInfo
         * \param SignerInfo
         * \return SignerInfoType
         */
        IssuerType get_type(const Issuer &);

        /**
         * \brief Calculates size of an CertificateDigestWithOtherAlgorithm
         * \param CertificateDigestWithOtherAlgorithm
         * \return number of octets needed to serialize the CertificateDigestWithOtherAlgorithm
         */
        size_t get_size(const CertificateDigestWithOtherAlgorithm &);

        /**
         * \brief Calculates size of an SignerInfo
         * \param SignerInfo
         * \return number of octets needed to serialize the SignerInfo
         */
        size_t get_size(const Issuer &);

        /**
         * \brief Serializes an CertificateDigestWithOtherAlgorithm into a binary archive
         */
        void serialize(OutputArchive &, const CertificateDigestWithOtherAlgorithm &);

        /**
         * \brief Serializes an SignerInfo into a binary archive
         */
        void serialize(OutputArchive &, const Issuer &);

        /**
         * \brief Deserializes an CertificateDigestWithOtherAlgorithm from a binary archive
         * \param archive with a CertificateDigestWithOtherAlgorithm at the beginning
         * \param CertificateDigestWithOtherAlgorithm to deserialize
         * \return size of the deserialized CertificateDigestWithOtherAlgorithm
         */
        size_t deserialize(InputArchive &, CertificateDigestWithOtherAlgorithm &);

        /**
         * \brief Deserializes an SignerInfo from a binary archive
         * \param archive with a SignerInfo at the beginning
         * \param SignerInfo to deserialize
         * \return size of the deserialized SignerInfo
         */
        size_t deserialize(InputArchive &, Issuer &);

    } // namespace security
} // namespace vanetza

#endif /* SIGNER_INFO_HPP_9K6GXK4R */
