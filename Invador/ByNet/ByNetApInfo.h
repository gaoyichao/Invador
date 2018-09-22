#ifndef BYNETAPINFO_H
#define BYNETAPINFO_H

#include <ByNetMacAddr.h>
#include <ByNetTypes.h>
#include <ByNetStInfo.h>
#include <pcap.h>
#include <map>

class ByNetApInfo
{
public:
    ByNetApInfo(unsigned char const *bssid);
    ~ByNetApInfo();

public:
    ByNetStInfo *FindStation(unsigned char *mac);
    ByNetStInfo *AddStation(unsigned char *mac);

public:
    int security; /* ENC_*, AUTH_*, STD_*     */

    unsigned long nb_bcn; /* total number of beacons  */
    unsigned long nb_pkt; /* total number of packets  */

    unsigned char bssid[6]; /* the access point's MAC   */
    unsigned char essid[MAX_IE_ELEMENT_SIZE];

    unsigned char lanip[4]; /* last detected ip address */
    struct WPS_info wps;

    // 新添加
    int crypt; /* encryption algorithm         */
    int eapol; /* set if EAPOL is present      */
    unsigned char *ivbuf; /* table holding WEP IV data    */
    struct WPA_hdsk wpa; /* valid WPA handshake data     */
    bool gotwpa;	// 成功捕获WPA握手包

    std::map<ByNetMacAddr, ByNetStInfo *> m_StMap;
};

#endif // BYNETAPINFO_H
