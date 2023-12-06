#ifndef VANETZA_CERTIFICATE_VALIDATION_HPP
#define VANETZA_CERTIFICATE_VALIDATION_HPP
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/trust_store.hpp>

namespace vanetza
{
    namespace security
    {
        boost::optional<validityPeriod> extract_validity_time(const Certificate &certificate);
        bool check_time_consistency(const Certificate &certificate, const Certificate &signer);
        bool check_subject_assurance_consistency(const Certificate &certificate, const Certificate &signer);
        bool check_region_consistency(const Certificate &certificate, const Certificate &signer);
        bool check_consistency(const Certificate &certificate, const Certificate &signer);
    }
}
#endif