#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <nss.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <vector>
#include <string>
#include "resolve.h"

struct SplitDNSRule {
    std::vector<std::string> domains;
    std::string nameserver;
};

struct SplitDNSRules {
    std::vector<SplitDNSRule> rules;
};

static SplitDNSRule rules;

static int
name_matches(const char *name, const char *reference_name)
{
    size_t len;

    if (name == NULL)
        return 0;

    /* Accept DNS names with an optional final dot. */
    len = strlen(name);
    if (len > 0 && name[len - 1] == '.')
        --len;

    if (len == strlen(reference_name) - 1 &&
        strncasecmp(name, reference_name, len) == 0)
        return 1;

    return 0;
}

/*
 * Allocate aligned storage from the caller's buffer.
 * No allocation escapes the lifetime of the NSS call.
 */
static void *
take(char **cursor, size_t *remaining,
     size_t size, size_t alignment)
{
    uintptr_t address = (uintptr_t) *cursor;
    size_t padding = (size_t)
        ((alignment - address % alignment) % alignment);

    if (padding > *remaining ||
        size > *remaining - padding)
        return NULL;

    *cursor += padding;
    *remaining -= padding;

    void *result = *cursor;
    *cursor += size;
    *remaining -= size;

    return result;
}

static char *
copy_string(char **cursor, size_t *remaining,
            const char *src)
{
    size_t len = strlen(src) + 1;
    char *dst = (char*)take(cursor, remaining, len, 1);

    if (dst != NULL)
        memcpy(dst, src, len);

    return dst;
}

static enum nss_status
not_found(int *errnop, int *herrnop)
{
    *errnop = ENOENT;
    *herrnop = HOST_NOT_FOUND;
    return NSS_STATUS_NOTFOUND;
}

static enum nss_status
buffer_too_small(int *errnop, int *herrnop)
{
    *errnop = ERANGE;
    *herrnop = NETDB_INTERNAL;
    return NSS_STATUS_TRYAGAIN;
}

/*
 * Construct a hostent with one address of the requested family.
 * All returned pointers refer to the caller-provided buffer.
 */
static enum nss_status
make_hostent(int af, struct hostent *result,
             char *buffer, size_t buflen,
             int *errnop, int *herrnop)
{
    char *cursor = buffer;
    size_t remaining = buflen;
    const char *address_text;
    size_t address_size;
    int address_family = af;

    if (af == AF_INET) {
        address_text = IPV4_TEXT;
        address_size = 4;
    } else if (af == AF_INET6) {
        address_text = IPV6_TEXT;
        address_size = 16;
    } else {
        *errnop = EAFNOSUPPORT;
        *herrnop = NO_DATA;
        return NSS_STATUS_UNAVAIL;
    }

    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (af == AF_INET) {
        if (inet_pton(AF_INET, address_text, &ipv4) != 1) {
            *errnop = EINVAL;
            *herrnop = NETDB_INTERNAL;
            return NSS_STATUS_UNAVAIL;
        }
    } else {
        if (inet_pton(AF_INET6, address_text, &ipv6) != 1) {
            *errnop = EINVAL;
            *herrnop = NETDB_INTERNAL;
            return NSS_STATUS_UNAVAIL;
        }
    }

    char *canonical = copy_string(
        &cursor, &remaining, CANONICAL_NAME);

    char *alias = copy_string(
        &cursor, &remaining, ALIAS_NAME);

    if (canonical == NULL || alias == NULL)
        return buffer_too_small(errnop, herrnop);

    /* One alias plus the terminating NULL. */
    char **aliases = (char**)take(
        &cursor, &remaining, 2 * sizeof(char *),
        _Alignof(char *));

    /* One address plus the terminating NULL. */
    char **addresses = (char**)take(
        &cursor, &remaining, 2 * sizeof(char *),
        _Alignof(char *));

    unsigned char *address = (unsigned char*)take(
        &cursor, &remaining, address_size, 1);

    if (aliases == NULL || addresses == NULL ||
        address == NULL)
        return buffer_too_small(errnop, herrnop);

    aliases[0] = alias;
    aliases[1] = NULL;

    if (address_family == AF_INET)
        memcpy(address, &ipv4, address_size);
    else
        memcpy(address, &ipv6, address_size);

    addresses[0] = (char *) address;
    addresses[1] = NULL;

    result->h_name = canonical;
    result->h_aliases = aliases;
    result->h_addrtype = address_family;
    result->h_length = (int) address_size;
    result->h_addr_list = addresses;

    *errnop = 0;
    *herrnop = NETDB_SUCCESS;
    return NSS_STATUS_SUCCESS;
}

/* Traditional IPv4/IPv6 hostname lookup interfaces. */

extern "C" enum nss_status
_nss_demo_gethostbyname3_r(
    const char *name, int af,
    struct hostent *result, char *buffer, size_t buflen,
    int *errnop, int *herrnop,
    int32_t *ttlp, char **canonp)
{
    if (!name_matches(name))
        return not_found(errnop, herrnop);

    enum nss_status status = make_hostent(
        af, result, buffer, buflen, errnop, herrnop);

    if (status == NSS_STATUS_SUCCESS) {
        if (ttlp != NULL)
            *ttlp = 0;  /* Static data; no DNS TTL. */

        if (canonp != NULL)
            *canonp = result->h_name;
    }

    return status;
}

extern "C" enum nss_status
_nss_demo_gethostbyname2_r(
    const char *name, int af,
    struct hostent *result, char *buffer, size_t buflen,
    int *errnop, int *herrnop)
{
    return _nss_demo_gethostbyname3_r(
        name, af, result, buffer, buflen,
        errnop, herrnop, NULL, NULL);
}

extern "C" enum nss_status
_nss_demo_gethostbyname_r(
    const char *name,
    struct hostent *result, char *buffer, size_t buflen,
    int *errnop, int *herrnop)
{
    return _nss_demo_gethostbyname2_r(
        name, AF_INET, result, buffer, buflen,
        errnop, herrnop);
}

/*
 * Modern glibc getaddrinfo fast path.
 * Return both IPv4 and IPv6 address tuples.
 */
extern "C" enum nss_status
_nss_demo_gethostbyname4_r(
    const char *name,
    struct gaih_addrtuple **pat,
    char *buffer, size_t buflen,
    int *errnop, int *herrnop, int32_t *ttlp)
{
    if (!name_matches(name))
        return not_found(errnop, herrnop);

    char *cursor = buffer;
    size_t remaining = buflen;

    struct gaih_addrtuple *v4 = (struct gaih_addrtuple *)take(
        &cursor, &remaining, sizeof(*v4),
        _Alignof(struct gaih_addrtuple));

    struct gaih_addrtuple *v6 = (struct gaih_addrtuple *)take(
        &cursor, &remaining, sizeof(*v6),
        _Alignof(struct gaih_addrtuple));

    char *canonical = copy_string(
        &cursor, &remaining, CANONICAL_NAME);

    if (v4 == NULL || v6 == NULL || canonical == NULL)
        return buffer_too_small(errnop, herrnop);

    memset(v4, 0, sizeof(*v4));
    memset(v6, 0, sizeof(*v6));

    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (inet_pton(AF_INET, IPV4_TEXT, &ipv4) != 1 ||
        inet_pton(AF_INET6, IPV6_TEXT, &ipv6) != 1) {
        *errnop = EINVAL;
        *herrnop = NETDB_INTERNAL;
        return NSS_STATUS_UNAVAIL;
    }

    v4->name = canonical;
    v4->family = AF_INET;
    memcpy(v4->addr, &ipv4, sizeof(ipv4));
    v4->next = v6;

    v6->name = canonical;
    v6->family = AF_INET6;
    memcpy(v6->addr, &ipv6, sizeof(ipv6));
    v6->next = NULL;

    *pat = v4;

    if (ttlp != NULL)
        *ttlp = 0;

    *errnop = 0;
    *herrnop = NETDB_SUCCESS;
    return NSS_STATUS_SUCCESS;
}
