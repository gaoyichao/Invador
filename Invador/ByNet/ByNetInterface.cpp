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
#include <byteorder.h>
#include <crypto.h>

#include <aircrack-util/common_util.h>
#include <aircrack-util/verifyssid.h>
#include <aircrack-util/mcs_index_rates.h>
#include <aircrack-osdep/common.h>
#include <uniqueiv.h>

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

void ByNetInterface::OpenRaw(int fd, int *arptype)
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

int ByNetInterface::Open()
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

    OpenRaw(fd_out, &arptype_out);

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

#include <radiotap_iter.h>

int ByNetInterface::Read(unsigned char *buf, int count, rx_info *ri)
{
    unsigned char tmpbuf[4096];

    if ((unsigned)count > sizeof(tmpbuf))
        return -1;

    int caplen = read(fd_in, tmpbuf, count);
    if (caplen < 0) {
        if (errno == EAGAIN)
            return 0;
        throw "ByNetInterface::Read failed!";
    }

    memset(buf, 0, count);
    if (NULL != ri)
        memset(ri, 0, sizeof(*ri));

    int got_signal = 0;
    int got_noise = 0;
    int got_channel = 0;
    int fcs_removed = 0;
    int n = 0;

    if (arptype_in == ARPHRD_IEEE80211_FULL) {
        struct ieee80211_radiotap_iterator iterator;
        struct ieee80211_radiotap_header *rthdr = (struct ieee80211_radiotap_header *) tmpbuf;

        if (ieee80211_radiotap_iterator_init(&iterator, rthdr, caplen, NULL) < 0)
            return (0);

        /* go through the radiotap arguments we have been given
         * by the driver
         */
        while (ri && (ieee80211_radiotap_iterator_next(&iterator) >= 0))
        {
            switch (iterator.this_arg_index) {
            case IEEE80211_RADIOTAP_TSFT:
                ri->ri_mactime = le64_to_cpu(*((uint64_t *) iterator.this_arg));
                break;
            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
            case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
                if (!got_signal) {
                    if (*iterator.this_arg < 127)
                        ri->ri_power = *iterator.this_arg;
                    else
                        ri->ri_power = *iterator.this_arg - 255;
                    got_signal = 1;
                }
                break;
            case IEEE80211_RADIOTAP_DBM_ANTNOISE:
            case IEEE80211_RADIOTAP_DB_ANTNOISE:
                if (!got_noise) {
                    if (*iterator.this_arg < 127)
                        ri->ri_noise = *iterator.this_arg;
                    else
                        ri->ri_noise = *iterator.this_arg - 255;
                    got_noise = 1;
                }
                break;
            case IEEE80211_RADIOTAP_ANTENNA:
                ri->ri_antenna = *iterator.this_arg;
                break;
            case IEEE80211_RADIOTAP_CHANNEL:
                ri->ri_channel = getChannelFromFrequency(
                        le16toh(*(uint16_t *) iterator.this_arg));
                got_channel = 1;
                break;
            case IEEE80211_RADIOTAP_RATE:
                ri->ri_rate = (*iterator.this_arg) * 500000;
                break;
            case IEEE80211_RADIOTAP_FLAGS:
                if (*iterator.this_arg & IEEE80211_RADIOTAP_F_FCS) {
                    fcs_removed = 1;
                    caplen -= 4;
                }
                if (*iterator.this_arg & IEEE80211_RADIOTAP_F_BADFCS)
                    return 0;
                break;
            }
        }

        n = le16_to_cpu(rthdr->it_len);

        if (n <= 0 || n >= caplen)
            return 0;
    }
    caplen -= n;

    //detect fcs at the end, even if the flag wasn't set and remove it
    if (fcs_removed == 0 && check_crc_buf_osdep(tmpbuf + n, caplen - 4) == 1)
    {
        caplen -= 4;
    }

    memcpy(buf, tmpbuf + n, caplen);

    if (ri && !got_channel)
        ri->ri_channel = m_channel;

    return caplen;
}



