#include <vanetza/security/trust_store.hpp>

namespace vanetza
{
    namespace security
    {

        void TrustStore::insert(const Certificate &certificate)
        {
            std::string id_name;
            // Get name
            for (auto &subject_attr : certificate.tobesigned)
            {
                toBeSignedType attr_type = get_type(subject_attr);
                if (attr_type == toBeSignedType::Name_id)
                {
                    NameId id = boost::get<NameId>(subject_attr);
                    if (id.name.size() > 0)
                    {
                        std::string subject_name(reinterpret_cast<const char *>(&id.name[0]), id.name.size());
                        id_name = subject_name;
                    }
                }
            }
            if (id_name != "Root-CA")
            {
                throw std::runtime_error("Only root certificate authorities may be added to the trust store");
            }

            HashedId8 id = calculate_hash(certificate);
            m_certificates.insert(std::make_pair(id, certificate));
        }

        std::list<Certificate> TrustStore::lookup(HashedId8 id) const
        {
            using iterator = std::multimap<HashedId8, Certificate>::const_iterator;
            std::pair<iterator, iterator> range = m_certificates.equal_range(id);

            std::list<Certificate> matches;
            for (auto item = range.first; item != range.second; ++item)
            {
                matches.push_back(item->second);
            }
            return matches;
        }

    } // namespace security
} // namespace vanetza
