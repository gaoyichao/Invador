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
    ByNetStInfo(ByNetMacAddr const &mac);
    ByNetStInfo *Clone() const;

public:
    ByNetApInfo *GetAp() { return m_ap; }
    void SetAp(ByNetApInfo *base) { m_ap = base; }
    bool IsConnected() const { return 0 != m_ap; }

    void SetMac(unsigned char const *mac) { m_mac.SetValue(mac); }
    void SetMac(ByNetMacAddr const &mac) { m_mac.SetValue(mac); }
    unsigned char *GetMacRaw() { return m_mac.GetValue(); }
    ByNetMacAddr const & GetMac() { return m_mac; }
private:
    ByNetApInfo *m_ap; /* AP this client belongs to */
    ByNetMacAddr m_mac; /* the client's MAC address  */
public:

    struct WPA_hdsk wpa; /* WPA handshake data        */
    int channel; /* Channel station is seen   */
};

#endif // BYNETSTINFO_H
