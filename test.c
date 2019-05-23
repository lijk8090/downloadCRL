#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <lber.h>
#include <ldap.h>

#ifndef PRINT_HEX
#define PRINT_HEX(buf, len)                                                                         \
    do{                                                                                             \
        if(buf != NULL && len > 0)                                                                  \
        {                                                                                           \
            int loop = 0;                                                                           \
            for(loop = 0; loop < len; loop++)                                                       \
                printf("0x%02hhx%s", (unsigned char)buf[loop], (loop+1) % 16 != 0 ? ", " : ",\n");  \
            if(loop % 16 != 0) printf("\n");                                                        \
        }                                                                                           \
    }while(0);
#endif

int crl_download_from_ldap(char *ip, unsigned short port, char *binddn, char *passwd, char *basedn4search, char *filter)
{
    int ret = 0;
    int version = LDAP_VERSION3;
    struct timeval timeout = {3, 0};

    LDAP *ld = NULL;
    LDAPMessage *msg = NULL;
    LDAPMessage *entry = NULL;

    ld = ldap_init(ip, port);
    if(ld == NULL)
    {
        fprintf(stderr, "ldap_init failed - \"%s:%hu\"\n", ip, port);
        return -1;
    }
    fprintf(stdout, "ldap_init succeed - \"%s:%hu\"\n", ip, port);

    ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &timeout);
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    ret = ldap_simple_bind_s(ld, binddn, passwd);
    if(ret != LDAP_SUCCESS)
    {
        fprintf(stderr, "ldap_simple_bind_s failed - %s; %s; %s\n", binddn, passwd, ldap_err2string(ret));
        goto ErrP;
    }

    ret = ldap_search_s(ld, basedn4search, LDAP_SCOPE_SUBTREE, filter, NULL, 0, &msg);
    if(ret != LDAP_SUCCESS)
    {
        fprintf(stderr, "ldap_search_s failed - %s; %s; %s\n", basedn4search, filter, ldap_err2string(ret));
        goto ErrP;
    }

    for(entry = ldap_first_entry(ld, msg); entry != NULL; entry = ldap_next_entry(ld, entry))
    {
        char *name = NULL;
        BerElement *ber = NULL;

        for(name = ldap_first_attribute(ld, entry, &ber); name != NULL; name = ldap_next_attribute(ld, entry, ber))
        {
            if(strcasecmp(name, "authorityRevocationList;binary") == 0 || strcasecmp(name, "certificateRevocationList;binary") == 0)
            {
                int i = 0;
                struct berval **values = NULL;

                values = ldap_get_values_len(ld, entry, name);
                if(values)
                {
                    int length = 0;
                    unsigned char buffer[65536] = {0};

                    for(i = 0; values[i] != NULL && values[i]->bv_val != NULL && values[i]->bv_len > 0; i++)
                    {
                        if(length + values[i]->bv_len > 65536)
                        {
                            fprintf(stderr, "Data overflow - %lu\n", length + values[i]->bv_len);
                            if(values) ldap_value_free_len(values);
                            if(name) ldap_memfree(name);
                            if(ber) ber_free(ber, 0);
                            goto ErrP;
                        }

                        memcpy(buffer + length, values[i]->bv_val, values[i]->bv_len);
                        length += values[i]->bv_len;
                    }
                    ldap_value_free_len(values);
                    PRINT_HEX(buffer, length);
                }
            }
            ldap_memfree(name);
        }
        if(ber) ber_free(ber, 0);
    }

    if(msg) ldap_msgfree(msg);
    if(ld) ldap_unbind_s(ld);
    return 0;
ErrP:
    if(msg) ldap_msgfree(msg);
    if(ld) ldap_unbind_s(ld);
    return -1;
}

int main(int argc, char *argv[])
{
    unsigned short port = LDAP_PORT;
    char *host = "10.20.91.171";
    char *binddn = "cn=admin,o=config";
    char *passwd = "novell";
    char *basedn = "cn=crl1,ou=crl,o=infosec,c=cn";
    char *filter = "(objectclass=cRLDistributionPoint)";

    return crl_download_from_ldap(host, port, binddn, passwd, basedn, filter);
}
