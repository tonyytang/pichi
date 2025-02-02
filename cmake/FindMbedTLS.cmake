find_path(MbedTLS_INCLUDE_DIRS NAMES mbedtls/version.h)

find_library(MbedTLS_LIBRARY NAMES mbedtls libmbedtls)
find_library(MbedTLS_CRYPTO_LIBRARY NAMES mbedcrypto libmbedcrypto)

if (MbedTLS_INCLUDE_DIRS)
  find_file(has_build_info "build_info.h" PATHS "${MbedTLS_INCLUDE_DIRS}/mbedtls")
  if (has_build_info)
    set(ver_file "${MbedTLS_INCLUDE_DIRS}/mbedtls/build_info.h")
  else ()
    set(ver_file "${MbedTLS_INCLUDE_DIRS}/mbedtls/version.h")
  endif ()
  file(STRINGS "${ver_file}" version_line
        REGEX "^#define[\t ]+MBEDTLS_VERSION_STRING[\t ]+\".*\"")
  if (version_line)
    string(REGEX REPLACE "^#define[\t ]+MBEDTLS_VERSION_STRING[\t ]+\"(.*)\""
            "\\1" MbedTLS_VERSION_STRING "${version_line}")
    unset(version_line)
  endif ()
endif ()

set(MbedTLS_LIBRARIES ${MbedTLS_LIBRARY} ${MbedTLS_CRYPTO_LIBRARY})
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MbedTLS
  REQUIRED_VARS MbedTLS_LIBRARY MbedTLS_CRYPTO_LIBRARY MbedTLS_INCLUDE_DIRS MbedTLS_VERSION_STRING
  VERSION_VAR MbedTLS_VERSION_STRING
)
