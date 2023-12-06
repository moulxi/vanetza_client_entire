#include <vanetza/security/exception.hpp>
#include <vanetza/security/tobesigned.hpp>
#include <iostream>

namespace vanetza
{
    namespace security
    {
        Duration::Duration() : m_raw(0)
        {
        }

        Duration::Duration(BitNumber<uint16_t, 13> value, Units unit) : m_raw(static_cast<decltype(m_raw)>(unit))
        {
            m_raw <<= 13;
            m_raw |= value.raw();
        }

        Duration::Duration(uint16_t raw) : m_raw(raw)
        {
        }

        std::chrono::seconds Duration::to_seconds() const
        {
            using std::chrono::seconds;

            // see section 4.2.17 of TS 103 097 v1.2.1 for conversion factors
            switch (unit())
            {
            case Units::Seconds:
                return seconds(value());

            case Units::Minutes:
                return seconds(value() * 60U);

            case Units::Hours:
                return seconds(value() * 3600U);

            case Units::Sixty_Hour_Blocks:
                return seconds(value() * 216000U);

            case Units::Years:
                return seconds(value() * 31556925ULL);

            default:
                // undefined, let's interpret it as minimal duration, which will fail during validation
                return std::chrono::seconds::min();
            }
        }
        // get_type
        toBeSignedType get_type(const toBeSigned &sub)
        {
            struct tobesigned_visitor : public boost::static_visitor<toBeSignedType>
            {
                toBeSignedType operator()(NameId id)
                {
                    return toBeSignedType::Name_id;
                }
                toBeSignedType operator()(CracaId cracaid)
                {
                    return toBeSignedType::Craca_Id;
                }
                toBeSignedType operator()(EncryptionKey encryptionkey)
                {
                    return toBeSignedType::Encryption_Key;
                }
                toBeSignedType operator()(assuranceLevel assurancelevel)
                {
                    return toBeSignedType::Assurance_Level;
                }
                toBeSignedType operator()(std::list<ItsAidSsp> list)
                {
                    return toBeSignedType::App_Permissions;
                }
                toBeSignedType operator()(validityPeriod validityperiod)
                {
                    return toBeSignedType::Validity_Period;
                }
                toBeSignedType operator()(GeographicRegion geographicregion)
                {
                    return toBeSignedType::Geographic_Region;
                }
                toBeSignedType operator()(VerificationKey verificationkey)
                {
                    return toBeSignedType::Verification_Key;
                }
            };

            tobesigned_visitor visit;
            return boost::apply_visitor(visit, sub);
        }

        // get_size
        size_t get_size(const assuranceLevel &assurance)
        {
            return sizeof(assurance.raw);
        }
        size_t get_size(const Duration &duration)
        {
            return sizeof(uint16_t);
        }
        size_t get_size(const validityPeriod &validity)
        {
            size_t size = sizeof(validity.start_validity);
            size += get_size(validity.duration);
            return size;
        }
        size_t get_size(const NameId &id)
        {
            size_t size = id.name.size();
            size += length_coding_size(id.name.size());
            return size;
        }
        size_t get_size(const ItsAidSsp &its_aid_ssp)
        {
            size_t size = get_size(its_aid_ssp.its_aid);
            size += its_aid_ssp.service_specific_permissions.size();
            size += length_coding_size(its_aid_ssp.service_specific_permissions.size());
            return size;
        }
        size_t get_size(const toBeSigned &sub)
        {
            size_t size = sizeof(toBeSignedType);
            struct tobesigned_visitor : public boost::static_visitor<size_t>
            {
                size_t operator()(const NameId &id)
                {
                    return get_size(id);
                }
                size_t operator()(const CracaId &cracaid)
                {
                    return cracaid.cracaid.size();
                }
                size_t operator()(const VerificationKey &key)
                {
                    return get_size(key.key);
                }
                size_t operator()(const EncryptionKey &key)
                {
                    return get_size(key.key);
                }
                size_t operator()(const assuranceLevel &assurance)
                {
                    return get_size(assurance);
                }
                size_t operator()(const std::list<ItsAidSsp> &list)
                {
                    size_t size = get_size(list);
                    size += length_coding_size(size);
                    return size;
                }
                size_t operator()(const validityPeriod &validity)
                {
                    return get_size(validity);
                }
                size_t operator()(const GeographicRegion &region)
                {
                    return get_size(region);
                }
            };

            tobesigned_visitor visit;
            size += boost::apply_visitor(visit, sub);
            return size;
        }
        // serialize
        void serialize(OutputArchive &ar, const ItsAidSsp &its_aid_ssp)
        {
            serialize(ar, its_aid_ssp.its_aid);
            size_t size = its_aid_ssp.service_specific_permissions.size();
            serialize_length(ar, size);
            for (auto &byte : its_aid_ssp.service_specific_permissions)
            {
                ar << byte;
            }
        }
        void serialize(OutputArchive &ar, const toBeSigned &tobeSigned)
        {
            struct tobesigned_visitor : public boost::static_visitor<>
            {
                tobesigned_visitor(OutputArchive &ar) : m_archive(ar)
                {
                }
                void operator()(const NameId &id)
                {
                    size_t size = id.name.size();
                    serialize_length(m_archive, size);
                    for (auto &byte : id.name)
                    {
                        m_archive << byte;
                    }
                }
                void operator()(const CracaId &cracaid)
                {
                    for (auto &byte : cracaid.cracaid)
                    {
                        m_archive << byte;
                    }
                }
                void operator()(const VerificationKey &key)
                {
                    serialize(m_archive, key.key);
                }
                void operator()(const EncryptionKey &key)
                {
                    serialize(m_archive, key.key);
                }
                void operator()(const assuranceLevel &assurance)
                {
                    m_archive << assurance.raw;
                }
                void operator()(const std::list<ItsAidSsp> &list)
                {
                    serialize(m_archive, list);
                }
                void operator()(const validityPeriod &validity)
                {
                    serialize(m_archive, host_cast(validity.start_validity));
                    serialize(m_archive, host_cast(validity.duration.raw()));
                }
                void operator()(const GeographicRegion &region)
                {
                    serialize(m_archive, region);
                }

                OutputArchive &m_archive;
            };

            toBeSignedType type = get_type(tobeSigned);
            serialize(ar, type);
            tobesigned_visitor visit(ar);
            boost::apply_visitor(visit, tobeSigned);
        }

        // deserialize
        size_t deserialize(InputArchive &ar, ItsAidSsp &its_aid_ssp)
        {
            size_t size = 0;
            size += deserialize(ar, its_aid_ssp.its_aid);
            const std::uintmax_t buf_size = deserialize_length(ar);
            its_aid_ssp.service_specific_permissions.resize(buf_size);
            size += buf_size + length_coding_size(buf_size);
            for (std::uintmax_t i = 0; i < buf_size; ++i)
            {
                ar >> its_aid_ssp.service_specific_permissions[i];
            }
            return size;
        }
        size_t deserialize(InputArchive &ar, NameId &id)
        {
            const std::uintmax_t size = deserialize_length(ar);

            for (uintmax_t c = 0; c < size; ++c)
            {
                uint8_t tmp;
                ar >> tmp;
                id.name.push_back(tmp);
            }
            return get_size(id);
        }
        size_t deserialize(InputArchive &ar, CracaId &cracaid)
        {
            for (size_t c = 0; c < 3; c++)
            {
                ar >> cracaid.cracaid[c];
            }
            size_t size = cracaid.cracaid.size();
            return size;
        }
        size_t deserialize(InputArchive &ar, toBeSigned &sub)
        {
            toBeSignedType type;
            size_t size = 0;
            deserialize(ar, type);
            size += sizeof(type);
            switch (type)
            {
            case toBeSignedType::Name_id:
            {
                NameId id;
                size += deserialize(ar, id);
                sub = id;
                break;
            }
            case toBeSignedType::Craca_Id:
            {
                CracaId cracaid;
                size += deserialize(ar, cracaid);
                sub = cracaid;
                break;
            }
            case toBeSignedType::Verification_Key:
            {
                VerificationKey key;
                size += deserialize(ar, key.key);
                sub = key;
                break;
            }
            case toBeSignedType::Encryption_Key:
            {
                EncryptionKey key;
                size += deserialize(ar, key.key);
                sub = key;
                break;
            }
            case toBeSignedType::Assurance_Level:
            {
                assuranceLevel assurance;
                ar >> assurance.raw;
                size += get_size(assurance);
                sub = assurance;
                break;
            }
            case toBeSignedType::App_Permissions:
            {
                std::list<ItsAidSsp> itsAidSsp_list;
                size_t tmp_size = deserialize(ar, itsAidSsp_list);
                size += tmp_size;
                size += length_coding_size(tmp_size);
                sub = itsAidSsp_list;
                break;
            }
            case toBeSignedType::Validity_Period:
            {
                validityPeriod validity;
                deserialize(ar, validity.start_validity);
                uint16_t duration;
                deserialize(ar, duration);
                validity.duration = Duration(duration);
                size += get_size(validity);
                sub = validity;
                break;
            }
            case toBeSignedType::Geographic_Region:
            {
                GeographicRegion region;
                size += deserialize(ar, region);
                sub = region;
                break;
            }
            default:
                throw deserialization_error("Unknown SubjectAttributeType");
            }

            return size;
        }
    }
}