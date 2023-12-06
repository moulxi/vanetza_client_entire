#include <vanetza/security/cert_validation.hpp>
#include <vanetza/security/tobesigned.hpp>
#include <iostream>
namespace vanetza
{
    namespace security
    {
        boost::optional<validityPeriod> extract_validity_time(const Certificate &certificate)
        {
            boost::optional<validityPeriod> restriction;
            for (auto &subject_attr : certificate.tobesigned)
            {
                toBeSignedType type = get_type(subject_attr);

                if (type == toBeSignedType::Validity_Period)
                {
                    // reject more than one restriction
                    if (restriction)
                    {
                        return boost::none;
                    }

                    restriction = boost::get<validityPeriod>(subject_attr);

                    // check if certificate validity restriction timestamps are logically correct
                    if (restriction->duration.to_seconds().count() <= 0)
                    {
                        return boost::none;
                    }
                }
            }
            return restriction;
        }
        bool check_time_consistency(const Certificate &certificate, const Certificate &signer)
        {
            boost::optional<validityPeriod> certificate_time = extract_validity_time(certificate);
            boost::optional<validityPeriod> signer_time = extract_validity_time(signer);
            if (!certificate_time || !signer_time)
            {
                return false;
            }

            if (signer_time->start_validity > certificate_time->start_validity)
            {
                return false;
            }
            auto certificate_time_end = boost::posix_time::seconds(certificate_time->start_validity) + boost::posix_time::seconds(certificate_time->duration.to_seconds().count());
            auto signer_time_end = boost::posix_time::seconds(signer_time->start_validity) + boost::posix_time::seconds(signer_time->duration.to_seconds().count());
            if (signer_time_end < certificate_time_end)
            {
                return false;
            }

            return true;
        }
        std::list<ItsAid> extract_application_identifiers(const Certificate &certificate)
        {
            std::list<ItsAid> aids;
            auto list = certificate.get_attribute<toBeSignedType::App_Permissions>();
            if (list)
            {
                for (auto &item : *list)
                {
                    aids.push_back(item.its_aid.get());
                }
            }
            return aids;
        }
        bool check_permission_consistency(const Certificate &certificate, const Certificate &signer)
        {
            auto certificate_aids = extract_application_identifiers(certificate);
            auto signer_aids = extract_application_identifiers(signer);
            auto compare = [](ItsAid a, ItsAid b)
            { return a < b; };

            certificate_aids.sort(compare);
            signer_aids.sort(compare);

            return std::includes(signer_aids.begin(), signer_aids.end(), certificate_aids.begin(), certificate_aids.end());
        }
        bool check_subject_assurance_consistency(const Certificate &certificate, const Certificate &signer)
        {
            auto certificate_assurance = certificate.get_attribute<toBeSignedType::Assurance_Level>();
            auto signer_assurance = signer.get_attribute<toBeSignedType::Assurance_Level>();

            if (!certificate_assurance || !signer_assurance)
            {
                return false;
            }

            if (certificate_assurance->assurance() > signer_assurance->assurance())
            {
                return false;
            }
            else if (certificate_assurance->assurance() == signer_assurance->assurance())
            {
                if (certificate_assurance->confidence() > signer_assurance->confidence())
                {
                    return false;
                }
            }

            return true;
        }
        bool check_region_consistency(const Certificate &certificate, const Certificate &signer)
        {
            auto certificate_region = certificate.get_attribute<toBeSignedType::Geographic_Region>();
            auto signer_region = signer.get_attribute<toBeSignedType::Geographic_Region>();

            if (!signer_region)
            {
                return true;
            }

            if (!certificate_region)
            {
                return false;
            }

            return is_within(*certificate_region, *signer_region);
        }
        bool check_consistency(const Certificate &certificate, const Certificate &signer)
        {
            if (!check_time_consistency(certificate, signer))
            {
                return false;
            }
            if (!check_permission_consistency(certificate, signer))
            {
                return false;
            }
            if (!check_subject_assurance_consistency(certificate, signer))
            {
                return false;
            }
            if (!check_region_consistency(certificate, signer))
            {
                return false;
            }

            return true;
        }
    }
}