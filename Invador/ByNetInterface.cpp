#include "ByNetInterface.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/wireless.h>

#include <netpacket/packet.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <iostream>

#include <utils.h>

ByNetInterface::ByNetInterface()
{
    m_iwpriv = NULL;
    m_iwconfig = NULL;
    m_ifconfig = NULL;
}

ByNetInterface::~ByNetInterface()
{
    if (NULL != m_iwpriv)
        delete m_iwpriv;
    if (NULL != m_iwconfig)
        delete m_iwconfig;
    if (NULL != m_ifconfig)
        delete m_ifconfig;
}

bool ByNetInterface::is_mac80211()
{
    char strbuf[512];
    memset(strbuf, 0, sizeof(strbuf));
    snprintf(strbuf, sizeof(strbuf) - 1,
             "ls /sys/class/net/%s/phy80211/subsystem >/dev/null 2>/dev/null",
             m_ifname.c_str());

     if (0 == system(strbuf)) {
        return true;
     }

     return false;
}

bool ByNetInterface::is_ipw2200()
{
    char strbuf[512];
    memset(strbuf, 0, sizeof(strbuf));
    snprintf(strbuf, sizeof(strbuf) - 1,
             "ls /sys/class/net/%s/inject >/dev/null 2>/dev/null",
             m_ifname.c_str());

     if (0 == system(strbuf)) {
        return true;
     }

     return false;
}

bool ByNetInterface::is_bcm43xx()
{
    char strbuf[512];
    memset(strbuf, 0, sizeof(strbuf));
    snprintf(strbuf, sizeof(strbuf) - 1,
             "ls /sys/class/net/%s/inject_nofcs >/dev/null 2>/dev/null",
             m_ifname.c_str());

     if (0 == system(strbuf)) {
        return true;
     }

     return false;
}

#ifndef ETH_P_80211_RAW
#define ETH_P_80211_RAW 25
#endif

#define ARPHRD_ETHERNET 1
#define ARPHRD_IEEE80211 801
#define ARPHRD_IEEE80211_PRISM 802
#define ARPHRD_IEEE80211_FULL 803

void ByNetInterface::openraw(int fd, int *arptype)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, m_ifname.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFINDEX, &ifr))
        throw "ioctl(SIOCGIFINDEX) failed";

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = m_ifindex;

    switch(m_drivertype) {
    case DT_IPW2200:
        break;
    case DT_BCM43XX:
        break;
    case DT_WLANNG:
        sll.sll_protocol = htons(ETH_P_80211_RAW);
        break;
    default:
        sll.sll_protocol = htons(ETH_P_ALL);
        break;
    }

    if (ioctl(fd, SIOCGIFHWADDR, &ifr))
        throw "ioctl(SIOCGIFHWADDR) failed";

    struct iwreq wrq;
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, m_ifname.c_str(), IFNAMSIZ - 1);
    wrq.ifr_name[IFNAMSIZ - 1] = 0;

    if (ioctl(fd, SIOCGIWMODE, &ifr) < 0) {
        /* most probably not supported (ie for rtap ipw interface) *
         * so just assume its correctly set...                     */
        wrq.u.mode = IW_MODE_MONITOR;
    }

    if ((ifr.ifr_flags | IFF_UP | IFF_BROADCAST | IFF_RUNNING) != ifr.ifr_flags) {
        ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING;
        if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
            throw "ioctl(SIOCSIFFLAGS) failed";
    }

    if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) < 0)
        throw "bind(ETH_P_ALL) failed";

    if (ioctl(fd, SIOCGIFHWADDR, &ifr))
        throw "ioctl(SIOCGIFHWADDR) failed";
    *arptype = ifr.ifr_hwaddr.sa_family;

    if (ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211
        && ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_PRISM
        && ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_FULL) {
        throw "expected ARPHRD_IEEE80211/ARPHRD_IEEE80211_PRISM/ARPHRD_IEEE80211_FULL";
    }

    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = m_ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
        throw "setsockopt(PACKET_MR_PROMISC) failed";


}

int ByNetInterface::open()
{
    if (m_ifname.length() >= IFNAMSIZ)
        throw "Interface name too long\n";

    fd_in = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd_in < 0)
        throw "socket(PF_PACKET) failed";

    fd_main = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd_main < 0)
        throw "socket(PF_PACKET) failed";

    fd_out = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd_out < 0)
        throw "socket(PF_PACKET) failed";

    m_iwpriv = get_witool_path("iwpriv");
    m_iwconfig = get_witool_path("iwconfig");
    m_ifconfig = get_witool_path("ifconfig");

    if (is_ndiswrapper(m_ifname.c_str(), m_iwpriv))
        throw "Nidswrapper不支持monitor模式!";

    if (is_mac80211())
        m_drivertype = DT_MAC80211_RT;
    if (is_ipw2200())
        m_drivertype = DT_IPW2200;
    if (is_bcm43xx())
        m_drivertype = DT_BCM43XX;

    openraw(fd_out, &arptype_out);

    if (m_drivertype != DT_BCM43XX && m_drivertype != DT_IPW2200) {
        close(fd_in);
        fd_in = fd_out;
    } else {
        int n = fd_out;
        fd_out = fd_in;
        fd_in = n;
    }
    arptype_in = arptype_out;

    return 0;
}






