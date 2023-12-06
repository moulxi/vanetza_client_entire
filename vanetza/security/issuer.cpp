#include <vanetza/security/certificate.hpp>
#include <vanetza/security/exception.hpp>
#include <vanetza/security/length_coding.hpp>
#include <vanetza/security/issuer.hpp>

namespace vanetza
{
    namespace security
    {

        IssuerType get_type(const Issuer &info)
        {
            struct Issuer_visitor : public boost::static_visitor<IssuerType>
            {
                IssuerType operator()(const std::nullptr_t)
                {
                    return IssuerType::Self;
                }
                IssuerType operator()(const HashedId8 &id)
                {
                    return IssuerType::Certificate_Digest_With_SHA256;
                }
                IssuerType operator()(const Certificate &cert)
                {
                    return IssuerType::Certificate;
                }
                IssuerType operator()(const std::list<Certificate> &list)
                {
                    return IssuerType::Certificate_Chain;
                }
                IssuerType operator()(const CertificateDigestWithOtherAlgorithm &cert)
                {
                    return IssuerType::Certificate_Digest_With_Other_Algorithm;
                }
            };

            Issuer_visitor visit;
            return boost::apply_visitor(visit, info);
        }
        size_t get_size(const CertificateDigestWithOtherAlgorithm &cert)
        {
            size_t size = cert.digest.size();
            size += sizeof(cert.algorithm);
            return size;
        }
        size_t get_size(const Issuer &info)
        {
            size_t size = sizeof(IssuerType);
            struct Issuer_visitor : public boost::static_visitor<size_t>
            {
                size_t operator()(const std::nullptr_t &)
                {
                    return 0;
                }
                size_t operator()(const HashedId8 &id)
                {
                    return id.size();
                }
                size_t operator()(const Certificate &cert)
                {
                    return get_size(cert);
                }
                size_t operator()(const std::list<Certificate> &list)
                {
                    size_t size = get_size(list);
                    size += length_coding_size(size);
                    return size;
                }
                size_t operator()(const CertificateDigestWithOtherAlgorithm &cert)
                {
                    return get_size(cert);
                }
            };

            Issuer_visitor visit;
            size += boost::apply_visitor(visit, info);
            return size;
        }

        void serialize(OutputArchive &ar, const CertificateDigestWithOtherAlgorithm &cert)
        {
            serialize(ar, cert.algorithm);
            for (auto &byte : cert.digest)
            {
                ar << byte;
            }
        }

        void serialize(OutputArchive &ar, const Issuer &info)
        {
            struct Issuer_visitor : public boost::static_visitor<>
            {
                Issuer_visitor(OutputArchive &ar) : m_archive(ar)
                {
                }

                void operator()(const std::nullptr_t)
                {
                    // intentionally do nothing
                }

                void operator()(const HashedId8 &id)
                {
                    for (auto &byte : id)
                    {
                        m_archive << byte;
                    }
                }
                void operator()(const Certificate &cert)
                {
                    serialize(m_archive, cert);
                }

                void operator()(const std::list<Certificate> &list)
                {
                    serialize(m_archive, list);
                }

                void operator()(const CertificateDigestWithOtherAlgorithm &cert)
                {
                    serialize(m_archive, cert);
                }

                OutputArchive &m_archive;
            };
            IssuerType type = get_type(info);
            serialize(ar, type);
            Issuer_visitor visit(ar);
            boost::apply_visitor(visit, info);
        }
        size_t deserialize(InputArchive &ar, CertificateDigestWithOtherAlgorithm &cert)
        {
            deserialize(ar, cert.algorithm);
            for (size_t c = 0; c < 8; c++)
            {
                ar >> cert.digest[c];
            }
            size_t size = cert.digest.size();
            size += sizeof(cert.algorithm);
            return size;
        }

        size_t deserialize(InputArchive &ar, Issuer &info)
        {
            IssuerType type;
            size_t size = 0;
            deserialize(ar, type);
            size += sizeof(IssuerType);
            switch (type)
            {
            case IssuerType::Certificate:
            {
                Certificate cert;
                size += deserialize(ar, cert);
                info = cert;
                break;
            }
            case IssuerType::Certificate_Chain:
            {
                std::list<Certificate> list;
                size += deserialize(ar, list);
                size += length_coding_size(size);
                info = list;
                break;
            }
            case IssuerType::Certificate_Digest_With_SHA256:
            {
                HashedId8 cert;
                for (size_t c = 0; c < 8; c++)
                {
                    ar >> cert[c];
                }
                info = cert;
                size += sizeof(cert);
                break;
            }
            case IssuerType::Certificate_Digest_With_Other_Algorithm:
            {
                CertificateDigestWithOtherAlgorithm cert;
                size += deserialize(ar, cert);
                info = cert;
                break;
            }
            case IssuerType::Self:
                info = nullptr;
                break;
            default:
                throw deserialization_error("Unknown IssuerType");
                break;
            }
            return size;
        }

    } // ns security
} // ns vanetza
