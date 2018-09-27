#ifndef BYNETMACADDR_H
#define BYNETMACADDR_H

#include <iostream>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <QObject>


class ByNetMacAddr {
public:
    ByNetMacAddr() {
        qRegisterMetaType<ByNetMacAddr>("ByNetMacAddr");
    }

    ByNetMacAddr(unsigned char const *addr) {
        qRegisterMetaType<ByNetMacAddr>("ByNetMacAddr");
        SetValue(addr);
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

    unsigned char const *GetValue() const { return m_addr; }
    unsigned char *GetValue() { return m_addr; }

    void SetValue(unsigned char const *addr) {
        char tmp[18];

        memcpy(m_addr, addr, 6);
        sprintf(tmp, "%02X:%02X:%02X:%02X:%02X:%02X",
                m_addr[0], m_addr[1], m_addr[2], m_addr[3], m_addr[4], m_addr[5]);

        m_str.clear();
        m_str.append(tmp);
    }

    void SetValue(ByNetMacAddr const & addr) {
        SetValue(addr.GetValue());
    }

    std::string const & GetStr() const { return m_str; }

private:
    unsigned char m_addr[6];
    std::string m_str;
};


#endif // BYNETMACADDR_H
