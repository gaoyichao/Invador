#ifndef BYNETCRYPTO_H
#define BYNETCRYPTO_H

#include <nl80211.h>

#define ByNet_ESSID_LENGTH 32

typedef struct {
    union {
        __u32 v[8];
        __u8 c[32];
    };
} wpapsk_hash;

#define CACHELINE_SIZE 64
#define MAX_KEYS_PER_CRYPT_SUPPORTED 1
#define CACHELINE_PADDED_FIELD(T, name, length, cacheline_size)           \
    T name [(length)];                                                      \
    __u8 name ## _padding [(cacheline_size) - ((length * sizeof(T)) % (cacheline_size))]

#pragma pack(push, 1)
struct ByNetCryptoData {
    /// Holds the pair-wise master key.
    CACHELINE_PADDED_FIELD(wpapsk_hash, pmk, MAX_KEYS_PER_CRYPT_SUPPORTED, CACHELINE_SIZE);
    /// Holds a 64-byte buffer for HMAC SHA1 ipad/opad, plus an extra 20-byte buffer for a SHA1 digest.
    CACHELINE_PADDED_FIELD(__u8, hash1, (64 + 20) * MAX_KEYS_PER_CRYPT_SUPPORTED, CACHELINE_SIZE);
    /// Holds a 20-byte buffer for a SHA1 digest. Half cache-line size is to compact with the next.
    CACHELINE_PADDED_FIELD(__u8, crypt1, 20 * MAX_KEYS_PER_CRYPT_SUPPORTED, CACHELINE_SIZE / 2);
    /// Holds a 20-byte buffer for a SHA1 digest. Half cache-line size is to compact with the previous.
    CACHELINE_PADDED_FIELD(__u8, crypt2, 20 * MAX_KEYS_PER_CRYPT_SUPPORTED, CACHELINE_SIZE / 2);
    /// Holds a 20-byte buffer for a SHA1 digest. Double cache-line size is to space the next field futher out.
    CACHELINE_PADDED_FIELD(__u8, ptk, 20 * MAX_KEYS_PER_CRYPT_SUPPORTED, CACHELINE_SIZE * 2);
    /// Holds a 100-byte buffer for pair-wise key expansion.
    CACHELINE_PADDED_FIELD(__u8, pke, 100 * MAX_KEYS_PER_CRYPT_SUPPORTED, CACHELINE_SIZE);
};
#pragma pack(pop)

class ByNetCrypto {
public:
    ByNetCrypto();
    ~ByNetCrypto();

public:
    void CalPke(__u8 const *bssid, __u8 const *stmac, __u8 const *anonce, __u8 const *snonce);
    void CalPmk(__u8 const *key);
    void CalPtk();
    void CalMic(const __u8 *eapol, const __u32 eapol_size, __u8 *mic);

public:
    __u8 const * GetESSID() const { return m_eSSID; }
    int GetESSIDLen() const { return m_eSSIDLen; }
    void SetESSID(__u8 const *essid);

    wpapsk_hash *__GetPmk() { return m_data.pmk; }
    __u8 *__GetPtk() { return m_data.ptk; }
private:
    __u8 *m_eSSID;
    int m_eSSIDLen;
    struct ByNetCryptoData m_data;
};


#endif // BYNETCRYPTO_H




