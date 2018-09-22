#ifndef BYNETMACADDR_H
#define BYNETMACADDR_H

#include <iostream>
#include <stdlib.h>
#include <string.h>

class ByNetMacAddr {
public:
    ByNetMacAddr(unsigned char const *addr) {
        memcpy(m_addr, addr, 6);
    }

    friend bool operator < (ByNetMacAddr const &a, ByNetMacAddr const &b) {
        return (memcmp(a.m_addr, b.m_addr, 6) < 0);
    }

    friend bool operator < (ByNetMacAddr const &a, unsigned char const *b) {
        return (memcmp(a.m_addr, b, 6) < 0);
    }

    friend bool operator < (unsigned char const *a, ByNetMacAddr const &b) {
        return (memcmp(a, b.m_addr, 6) < 0);
    }

private:
    unsigned char m_addr[6];
};

#endif // BYNETMACADDR_H
