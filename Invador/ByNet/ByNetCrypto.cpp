#include <ByNetCrypto.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <stdlib.h>
#include <string.h>
#include <cassert>


ByNetCrypto::ByNetCrypto()
{
    m_eSSID = (__u8*)malloc(ByNet_ESSID_LENGTH + 1);
    memset(m_eSSID, 0, ByNet_ESSID_LENGTH + 1);
    m_eSSIDLen = 0;

    memset(&m_data, 0, sizeof(m_data));
}

ByNetCrypto::~ByNetCrypto()
{
    free(m_eSSID);
}

void ByNetCrypto::SetESSID(const __u8 *essid)
{
    assert(0 != essid);

    memset(m_eSSID, 0, ByNet_ESSID_LENGTH + 1);
    m_eSSIDLen = 0;

    memccpy(m_eSSID, essid, 0, ByNet_ESSID_LENGTH);
    m_eSSIDLen = strlen((char *)m_eSSID);
}

void ByNetCrypto::CalPke(const __u8 *bssid, const __u8 *stmac, const __u8 *anonce, const __u8 *snonce)
{
    __u8 *pke = m_data.pke;

    /* pre-compute the key expansion buffer */
    memcpy(pke, "Pairwise key expansion", 23);

    if (memcmp(stmac, bssid, 6) < 0) {
        memcpy(pke + 23, stmac, 6);
        memcpy(pke + 29, bssid, 6);
    } else {
        memcpy(pke + 23, bssid, 6);
        memcpy(pke + 29, stmac, 6);
    }

    if (memcmp(snonce, anonce, 32) < 0) {
        memcpy(pke + 35, snonce, 32);
        memcpy(pke + 67, anonce, 32);
    } else {
        memcpy(pke + 35, anonce, 32);
        memcpy(pke + 67, snonce, 32);
    }
}

void ByNetCrypto::CalPmk(const __u8 *key)
{
    __u8 *pmk = (__u8*)m_data.pmk;

    char essid[33+4];
    memset(essid, 0, sizeof(essid));
    memcpy(essid, m_eSSID, m_eSSIDLen);
    int slen = m_eSSIDLen + 4;

    /* setup the inner and outer contexts */
    unsigned char buffer[65];
    memset(buffer, 0, sizeof(buffer));
    strncpy((char*)buffer, (char*)key, sizeof(buffer) - 1);

    SHA_CTX ctx_ipad;
    SHA_CTX ctx_opad;
    SHA_CTX sha1_ctx;

    for(int i = 0; i < 64; i++)
        buffer[i] ^= 0x36;
    SHA1_Init(&ctx_ipad);
    SHA1_Update(&ctx_ipad, buffer, 64);

    for (int i = 0; i < 64; i++)
        buffer[i] ^= 0x6A;
    SHA1_Init(&ctx_opad);
    SHA1_Update(&ctx_opad, buffer, 64);

    /* iterate HMAC-SHA1 over itself 8192 times */
    essid[slen - 1] = '\1';
    HMAC(EVP_sha1(), key, (int)strlen((char*)key), (unsigned char*)essid, slen, pmk, 0);
    memcpy(buffer, pmk, 20);
    for (int i = 1; i < 4096; i++) {
        memcpy(&sha1_ctx, &ctx_ipad, sizeof(sha1_ctx));
        SHA1_Update(&sha1_ctx, buffer, 20);
        SHA1_Final(buffer, &sha1_ctx);

        memcpy(&sha1_ctx, &ctx_opad, sizeof(sha1_ctx));
        SHA1_Update(&sha1_ctx, buffer, 20);
        SHA1_Final(buffer, &sha1_ctx);

        for (int j = 0; j < 20; j++)
            pmk[j] ^= buffer[j];
    }

    essid[slen - 1] = '\2';
    HMAC(EVP_sha1(), key, (int)strlen((char*)key), (unsigned char*)essid, slen, pmk+20, 0);
    memcpy(buffer, pmk+20, 20);
    for (int i = 1; i < 4096; i++) {
        memcpy(&sha1_ctx, &ctx_ipad, sizeof(sha1_ctx));
        SHA1_Update(&sha1_ctx, buffer, 20);
        SHA1_Final(buffer, &sha1_ctx);

        memcpy(&sha1_ctx, &ctx_opad, sizeof(sha1_ctx));
        SHA1_Update(&sha1_ctx, buffer, 20);
        SHA1_Final(buffer, &sha1_ctx);

        for (int j = 0; j < 20; j++)
            pmk[j + 20] ^= buffer[j];
    }
}

void ByNetCrypto::CalPtk()
{
    __u8 *ptk = m_data.ptk;
    wpapsk_hash *pmk = m_data.pmk;

    for (unsigned char i = 0; i < 1; i++) {
        *(m_data.pke + 99) = i;

        HMAC(EVP_sha1(), pmk, 32, m_data.pke, 100, ptk + i * 20, 0);
    }
}

void ByNetCrypto::CalMic(const __u8 *eapol, const __u32 eapol_size, __u8 *mic)
{
    __u8 *ptk = m_data.ptk;


    HMAC(EVP_sha1(), ptk, 16, eapol, eapol_size, mic, 0);
}





