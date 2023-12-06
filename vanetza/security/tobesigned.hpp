#ifndef TOBESIGNED_HPP_IRZLEB7C
#define TOBESIGNED_HPP_IRZLEB7C
#include <vanetza/common/bit_number.hpp>
#include <vanetza/security/region.hpp>
#include <vanetza/security/serialization.hpp>
#include <vanetza/security/int_x.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <boost/variant/variant.hpp>
#include <chrono>
#include <cstdint>
#include <list>

namespace vanetza
{

    namespace security
    {
        class Duration
        {
        public:
            enum class Units
            {
                Seconds = 0x0,
                Minutes = 0x1,
                Hours = 0x2,
                Sixty_Hour_Blocks = 0x3,
                Years = 0x4
            };

            Duration();
            Duration(BitNumber<uint16_t, 13> value, Units unit);
            Duration(uint16_t raw);

            uint16_t raw() const
            {
                return m_raw;
            }

            /**
             * Get duration's unit.
             * \return unit part of raw value
             */
            Units unit() const
            {
                return static_cast<Units>(m_raw >> 13);
            }

            /**
             * Get duration's ticks value
             * \return value part of raw value
             */
            uint16_t value() const
            {
                return m_raw & 0x1FFF; // mask upper 3 bit
            }

            /**
             * Convert duration to seconds.
             * \note std::chrono::seconds is wide enough to represent 2^13 years
             * \return duration in seconds
             */
            std::chrono::seconds to_seconds() const;

        private:
            uint16_t m_raw;
        };
        size_t get_size(const Duration &);
        struct assuranceLevel
        {
            assuranceLevel(uint8_t _raw = 0) : raw(_raw) {}

            static constexpr uint8_t assurance_mask = 0xE0;
            static constexpr uint8_t confidence_mask = 0x03;

            uint8_t raw;

            uint8_t assurance() const
            {
                return (raw & assurance_mask) >> 5;
            }

            uint8_t confidence() const
            {
                return raw & confidence_mask;
            }
        };

        struct VerificationKey
        {
            PublicKey key;
        };
        struct EncryptionKey
        {
            PublicKey key;
        };
        struct NameId
        {
            ByteBuffer name;
        };
        struct CracaId
        {
            HashedId3 cracaid;
        };
        struct validityPeriod
        {
            validityPeriod() = default;
            validityPeriod(Time32 start, Duration);

            Time32 start_validity;
            Duration duration;
        };
        struct ItsAidSsp
        {
            IntX its_aid;
            ByteBuffer service_specific_permissions;
        };
        enum class toBeSignedType : uint8_t
        {
            Name_id = 0,         // CertificateId
            Craca_Id = 1,        // HashedId3
            Encryption_Key = 2,  // PublicEncryptionKey
            Assurance_Level = 3, // SubjectAssurance
            App_Permissions = 4,
            Validity_Period = 5,   // ValidityPeriod
            Geographic_Region = 6, // GeographicRegion
            Verification_Key = 7,  // VerificationKeyIndicator
        };
        using toBeSigned = boost::variant<
            NameId,
            CracaId,
            EncryptionKey,
            assuranceLevel,
            std::list<ItsAidSsp>,
            validityPeriod,
            GeographicRegion,
            VerificationKey>;

        toBeSignedType get_type(const toBeSigned &);
        size_t get_size(const toBeSigned &);
        size_t get_size(const assuranceLevel &);
        size_t get_size(const validityPeriod &);
        size_t get_size(const NameId &);
        size_t get_size(const Duration &);
        size_t get_size(const ItsAidSsp &);

        size_t deserialize(InputArchive &, toBeSigned &);
        size_t deserialize(InputArchive &, CracaId &);
        size_t deserialize(InputArchive &, NameId &);
        size_t deserialize(InputArchive &, ItsAidSsp &);

        void serialize(OutputArchive &, const toBeSigned &);
        void serialize(OutputArchive &, const ItsAidSsp &);
        // void serialize(OutputArchive &, const NameId &);

        namespace detail
        {
            template <toBeSignedType>
            struct tobesigned_type;

            template <>
            struct tobesigned_type<toBeSignedType::Name_id>
            {
                using type = NameId;
            };

            template <>
            struct tobesigned_type<toBeSignedType::Craca_Id>
            {
                using type = CracaId;
            };

            template <>
            struct tobesigned_type<toBeSignedType::Encryption_Key>
            {
                using type = EncryptionKey;
            };

            template <>
            struct tobesigned_type<toBeSignedType::Assurance_Level>
            {
                using type = assuranceLevel;
            };
            template <>
            struct tobesigned_type<toBeSignedType::App_Permissions>
            {
                using type = std::list<ItsAidSsp>;
            };
            template <>
            struct tobesigned_type<toBeSignedType::Validity_Period>
            {
                using type = validityPeriod;
            };

            template <>
            struct tobesigned_type<toBeSignedType::Geographic_Region>
            {
                using type = GeographicRegion;
            };

            template <>
            struct tobesigned_type<toBeSignedType::Verification_Key>
            {
                using type = VerificationKey;
            };
        }

        /**
         * \brief resolve type for matching SubjectAttributeType
         *
         * This is kind of the reverse function of get_type(const SubjectAttribute&)
         */
        template <toBeSignedType T>
        using tobesigned_type = typename detail::tobesigned_type<T>::type;
    }
}

#endif