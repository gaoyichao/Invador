#ifndef BYNETSTINFO_H
#define BYNETSTINFO_H

#include <ByNetMacAddr.h>
#include <ByNetTypes.h>
#include <pcap.h>
#include <string>
#include <set>

class ByNetStInfo
{
public:
    ByNetStInfo(unsigned char const *mac);
    ByNetStInfo *Clone() const;

public:
    ByNetApInfo *GetAp() { return m_base; }
    void SetAp(ByNetApInfo *base) { m_base = base; }
    bool IsConnected() const { return 0 != m_base; }
private:
    ByNetApInfo *m_base; /* AP this client belongs to */
public:
    unsigned char stmac[6]; /* the client's MAC address  */

    struct WPA_hdsk wpa; /* WPA handshake data        */
    int channel; /* Channel station is seen   */
};

#endif // BYNETSTINFO_H
