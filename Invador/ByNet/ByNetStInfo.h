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
public:
    ByNetApInfo *base; /* AP this client belongs to */
    unsigned char stmac[6]; /* the client's MAC address  */

    struct WPA_hdsk wpa; /* WPA handshake data        */
    int channel; /* Channel station is seen   */
};

#endif // BYNETSTINFO_H
