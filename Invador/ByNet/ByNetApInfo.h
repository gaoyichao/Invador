#ifndef BYNETAPINFO_H
#define BYNETAPINFO_H

#include <ByNetMacAddr.h>
#include <ByNetTypes.h>
#include <ByNetStInfo.h>
#include <pcap.h>
#include <map>
#include <string>

class ByNetApInfo
{
public:
    ByNetApInfo(unsigned char const *bssid);
    ByNetApInfo(ByNetMacAddr const & bssid);
    ~ByNetApInfo();

public:
    ByNetStInfo *FindStation(unsigned char *mac);
    ByNetStInfo *AddStation(ByNetStInfo *st);
    int NumStation() const { return m_StMap.size(); }

    ByNetApInfo *Clone() const;

public:
    int security; /* ENC_*, AUTH_*, STD_*     */

    unsigned long nb_bcn; /* total number of beacons  */
    unsigned long nb_pkt; /* total number of packets  */

    unsigned char essid[MAX_IE_ELEMENT_SIZE];

    unsigned char lanip[4]; /* last detected ip address */
    struct WPS_info wps;

    // 新添加
    int crypt; /* encryption algorithm         */
    int eapol; /* set if EAPOL is present      */
    struct WPA_hdsk wpa; /* valid WPA handshake data     */
    bool gotwpa;	// 成功捕获WPA握手包

public:
    void SetBssid(unsigned char const *bssid) { m_bssid.SetValue(bssid); }
    void SetBssid(ByNetMacAddr const &bssid) { m_bssid.SetValue(bssid); }
    unsigned char *GetBssidRaw() { return m_bssid.GetValue(); }
    ByNetMacAddr const & GetBssid() { return m_bssid; }
private:
    std::map<ByNetMacAddr, ByNetStInfo *> m_StMap;
    ByNetMacAddr m_bssid;
};

#endif // BYNETAPINFO_H
