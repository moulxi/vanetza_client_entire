add_vanetza_component(security
    backend.cpp
    backend_null.cpp
    basic_elements.cpp
    cam_ssp.cpp
    certificate.cpp
    certificate_cache.cpp
    default_certificate_validator.cpp
    delegating_security_entity.cpp
    ecc_point.cpp
    ecdsa256.cpp
    encryption_parameter.cpp
    header_field.cpp
    int_x.cpp
    length_coding.cpp
    naive_certificate_provider.cpp
    # null_certificate_provider.cpp
    # null_certificate_validator.cpp
    payload.cpp
    persistence.cpp
    public_key.cpp
    recipient_info.cpp
    region.cpp
    secured_message.cpp
    serialization.cpp
    sha.cpp
    signature.cpp
    sign_header_policy.cpp
    sign_service.cpp
    static_certificate_provider.cpp
    trailer_field.cpp
    trust_store.cpp
    # validity_restriction.cpp
    verify_service.cpp
    issuer.cpp
    tobesigned.cpp
    cert_validation.cpp
)
target_link_libraries(security PUBLIC common net)
target_link_libraries(security PRIVATE GeographicLib::GeographicLib)

# crypto++ is a public mandatory dependency because of "NaiveCertificateProvider"
if(TARGET CryptoPP::CryptoPP)
    set_property(TARGET security APPEND PROPERTY
        SOURCES backend_cryptopp.cpp)
    target_link_libraries(security PUBLIC CryptoPP::CryptoPP)
    target_compile_definitions(security PUBLIC "VANETZA_WITH_CRYPTOPP")
endif()

if(TARGET OpenSSL::Crypto)
    set_property(TARGET security APPEND PROPERTY
        SOURCES backend_openssl.cpp openssl_wrapper.cpp)
    target_link_libraries(security PRIVATE OpenSSL::Crypto)
    target_compile_definitions(security PUBLIC "VANETZA_WITH_OPENSSL")
    if ("${OPENSSL_VERSION}" VERSION_EQUAL 2.0.0)
        # found LibreSSL most likely, should be API compatible to OpenSSL 1.0.1
        target_compile_definitions(security PRIVATE "OPENSSL_API_COMPAT=0x10000000L")
    elseif ("${OPENSSL_VERSION}" VERSION_EQUAL 1.1.1)
        target_compile_definitions(security PRIVATE "OPENSSL_API_COMPAT=0x10101000L")
    elseif ("${OPENSSL_VERSION}" VERSION_LESS 1.1.0)
        target_compile_definitions(security PRIVATE "OPENSSL_API_COMPAT=0x10000000L")
    else()
        target_compile_definitions(security PRIVATE "OPENSSL_API_COMPAT=0x10100000L")
    endif()
endif()

add_test_subdirectory(tests)
