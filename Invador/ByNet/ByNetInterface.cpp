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

    ap_1st = NULL;
    ap_end = NULL;
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

struct AP_info *ByNetInterface::FindAp(unsigned char *bssid)
{
    struct AP_info *ap_cur = ap_1st;
    while (NULL != ap_cur) {
        if (!memcmp(ap_cur->bssid, bssid, 6))
            break;
        ap_cur = ap_cur->next;
    }
    return ap_cur;
}

struct AP_info *ByNetInterface::AddAp(unsigned char *bssid)
{
    struct AP_info *ap_prv = ap_end;
    struct AP_info *ap_cur = (struct AP_info *)malloc(sizeof(struct AP_info));

    if (0 == ap_cur)
        throw "ByNetInterface::AddAp malloc failed";

    memset(ap_cur, 0, sizeof(struct AP_info));

    if (NULL == ap_1st)
        ap_1st = ap_cur;
    else
        ap_prv->next = ap_cur;

    ap_cur->prev = ap_prv;
    ap_end = ap_cur;

    memcpy(ap_cur->bssid, bssid, 6);
    ap_cur->nb_pkt = 0;
    ap_cur->tinit = time(NULL);
    ap_cur->tlast = time(NULL);

    ap_cur->ssid_length = 0;
    ap_cur->essid_stored = 0;
    memset(ap_cur->essid, 0, MAX_IE_ELEMENT_SIZE);
    ap_cur->timestamp = 0;

    /* 802.11n and ac */
    ap_cur->channel_width = CHANNEL_22MHZ; // 20MHz by default
    memset(ap_cur->standard, 0, 3);

    ap_cur->n_channel.sec_channel = -1;
    ap_cur->n_channel.short_gi_20 = 0;
    ap_cur->n_channel.short_gi_40 = 0;
    ap_cur->n_channel.any_chan_width = 0;
    ap_cur->n_channel.mcs_index = -1;

    ap_cur->ac_channel.center_sgmt[0] = 0;
    ap_cur->ac_channel.center_sgmt[1] = 0;
    ap_cur->ac_channel.mu_mimo = 0;
    ap_cur->ac_channel.short_gi_80 = 0;
    ap_cur->ac_channel.short_gi_160 = 0;
    ap_cur->ac_channel.split_chan = 0;
    ap_cur->ac_channel.mhz_160_chan = 0;
    ap_cur->ac_channel.wave_2 = 0;
    memset(ap_cur->ac_channel.mcs_index, 0, MAX_AC_MCS_INDEX);

    return ap_cur;
}

struct ST_info *ByNetInterface::FindStation(unsigned char *mac)
{
    struct ST_info *st_cur = st_1st;
    while (NULL != st_cur) {
        if (!memcmp(st_cur->stmac, mac, 6))
            break;
        st_cur = st_cur->next;
    }
    return st_cur;
}

struct ST_info *ByNetInterface::AddStation(unsigned char *mac)
{
    struct ST_info *st_cur = (struct ST_info *)malloc(sizeof(struct ST_info));
    struct ST_info *st_prv = st_end;

    if (0 == st_cur)
        throw "ByNetInterface::AddStation malloc failed";

    memset(st_cur, 0, sizeof(struct ST_info));

    if (NULL == st_1st)
        st_1st = st_cur;
    else
        st_prv->next = st_cur;

    st_cur->prev = st_prv;
    st_end = st_cur;

    memcpy(st_cur->stmac, mac, 6);
    st_cur->nb_pkt = 0;
    st_cur->tinit = time(NULL);
    st_cur->tlast = time(NULL);

    st_cur->power = -1;
    st_cur->best_power = -1;
    st_cur->rate_to = -1;
    st_cur->rate_from = -1;

    st_cur->probe_index = -1;
    st_cur->missed = 0;
    st_cur->lastseq = 0;
    st_cur->qos_fr_ds = 0;
    st_cur->qos_to_ds = 0;
    st_cur->channel = 0;

    return st_cur;
}



const unsigned char llcnull[4] = {0, 0, 0, 0};
#include <stdio.h>

int ByNetInterface::DumpPacket(unsigned char *buf, int caplen, rx_info *ri, FILE *f_cap)
{
    int seq, n, i, type, length, offset, numuni, numauth;
    unsigned z;
    struct AP_info *ap_cur;
    struct ST_info *st_cur;

    unsigned char c;
    unsigned char *p, *org_p;
    unsigned char bssid[6];
    unsigned char stmac[6];
    struct pcap_pkthdr pkh;
    struct timeval tv;

    // todo: 主动扫描模式暂未实现

    /* skip packets smaller than a 802.11 header */
    if (caplen < 24)
        return 1;

    /* skip (uninteresting) control frames */
    if (0x04 == (buf[0] & 0x0C))
        return 2;

    /* if it's a LLC null packet, just forget it (may change in the future) */
    if (caplen > 128) {
        if (memcmp(buf + 24, llcnull, 4) == 0)
            return 0;
    }

    /* grab the sequence number */
    seq = (buf[22] >> 4) + (buf[23] << 4);

    /* locate the access point's MAC address */
    switch (buf[1] & 3) {
    case 0: // Adhoc
        memcpy(bssid, buf + 16, 6);
        break;
    case 1: // ToDS
        memcpy(bssid, buf + 4, 6);
        break;
    case 2: // FromDS
        memcpy(bssid, buf + 10, 6);
        break;
    case 3: // WDS -> Transmitter taken as BSSID
        memcpy(bssid, buf + 10, 6);
        break;
    }

    /* update our chained list of access points */
    ap_cur = FindAp(bssid);
    if (NULL == ap_cur)
        ap_cur = AddAp(bssid);

    ap_cur->tlast = time(NULL);

    // todo: 更新ap信号强度

    switch (buf[0]) {
    case 0x80:
        ap_cur->nb_pkt++;
        break;
    case 0x50:
        /* reset the WPS state */
        ap_cur->wps.state = 0xFF;
        ap_cur->wps.ap_setup_locked = 0;
        break;
    }
    ap_cur->nb_pkt++;

    /* locate the station MAC in the 802.11 header */
    switch (buf[1] & 3) {
    case 0:
        /* if management, check that SA != BSSID */
        if (memcmp(buf + 10, bssid, 6) == 0)
            goto skip_station;
        memcpy(stmac, buf + 10, 6);
        break;
    case 1:
        /* ToDS packet, must come from a client */
        memcpy(stmac, buf + 10, 6);
        break;
    case 2:
        /* FromDS packet, reject broadcast MACs */
        if ((buf[4] % 2) != 0)
            goto skip_station;
        memcpy(stmac, buf + 4, 6);
        break;
    default:
        goto skip_station;
        break;
    }

    /* update our chained list of wireless stations */
    st_cur = FindStation(stmac);
    if (NULL == st_cur)
        st_cur = AddStation(stmac);

    st_cur->tlast = time(NULL);

    if (st_cur->base == NULL || memcmp(ap_cur->bssid, BROADCAST, 6) != 0)
        st_cur->base = ap_cur;
    if ((st_cur != NULL) && (buf[1] & 3) == 2)
        st_cur->rate_to = ri->ri_rate;

    st_cur->nb_pkt++;
    // todo: 更新station信号强度

skip_station:
    /* packet parsing: Probe Request */
    if (buf[0] == 0x40 && st_cur != NULL) {
        //printf(">>> Probe Request\n");

        p = buf + 24;
        while (p < buf + caplen) {
            if (p + 2 + p[1] > buf + caplen)
                break;

            if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0' && (p[1] > 1 || p[2] != ' ')) {
                n = p[1];

                for (i = 0; i < n; i++) {
                    if (p[2+i] > 0 && p[2+i] < ' ')
                        goto skip_probe;
                }

                /* got a valid ASCII probed ESSID, check if it's already in the ring buffer */
                for (i = 0; i < NB_PRB; i++) {
                    if (0 == memcmp(st_cur->probes[i], p+2, n))
                        goto skip_probe;
                }

                st_cur->probe_index = (st_cur->probe_index + 1) % NB_PRB;
                memset(st_cur->probes[st_cur->probe_index], 0, MAX_IE_ELEMENT_SIZE);
                memcpy(st_cur->probes[st_cur->probe_index], p + 2, n); //twice?!
                st_cur->ssid_length[st_cur->probe_index] = n;

                if (0 == verifyssid((const unsigned char*)st_cur->probes[st_cur->probe_index])) {
                    for (i = 0; i < n; i++) {
                        c = p[2+i];
                        if (0 == c || (c > 0 && c < 32) || (c > 126 && c < 160))
                            c = '.';
                        st_cur->probes[st_cur->probe_index][i] = c;
                    }
                }
                //printf(">>> ssid_length = %d, probe_index = %d, %s\n",
                //       st_cur->ssid_length[st_cur->probe_index], st_cur->probe_index, st_cur->probes[st_cur->probe_index]);
            }
            p += 2 + p[1];
        }
    }

skip_probe:
    /* packet parsing: Beacon or Probe Response */
    if (buf[0] == 0x80 || buf[0] == 0x50) {
        if (!(ap_cur->security & (STD_OPN | STD_WEP | STD_WPA | STD_WPA2))) {
            if ((buf[34] & 0x10) >> 4)
                ap_cur->security |= STD_WEP | ENC_WEP;
            else
                ap_cur->security |= STD_OPN;
        }

        ap_cur->preamble = (buf[34] & 0x20) >> 5;
        unsigned long long *tstamp = (unsigned long long *) (buf + 24);
        ap_cur->timestamp = letoh64(*tstamp);
        p = buf + 36;

        while (p < buf + caplen) {
            if (p + 2 + p[1] > buf + caplen)
                break;

            // only update the essid length if the new length is > the old one
            if (p[0] == 0x00 && (ap_cur->ssid_length < p[1]))
                ap_cur->ssid_length = p[1];

            if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0' && (p[1] > 1 || p[2] != ' ')) {
                /* found a non-cloaked ESSID */
                n = p[1];

                memset(ap_cur->essid, 0, MAX_IE_ELEMENT_SIZE);
                memcpy(ap_cur->essid, p+2, n);

                // todo: store ivs file
            }


            /* get the maximum speed in Mb and the AP's channel */
            if (p[0] == 0x01 || p[0] == 0x32) {
                if (ap_cur->max_speed < (p[1 + p[1]] & 0x7F) / 2)
                    ap_cur->max_speed = (p[1 + p[1]] & 0x7F) / 2;
            }

            if (p[0] == 0x03) {
                ap_cur->channel = p[2];
            } else if (p[0] == 0x3d) {
                if (ap_cur->standard[0] == '\0')
                    ap_cur->standard[0] = 'n';

                /* also get the channel from ht information->primary channel */
                ap_cur->channel = p[2];

                // Get channel width and secondary channel
                switch (p[3] % 4) {
                case 0: // 20MHz
                    ap_cur->channel_width = CHANNEL_20MHZ;
                    break;
                case 1: // Above
                    ap_cur->n_channel.sec_channel = 1;
                    switch (ap_cur->channel_width) {
                        case CHANNEL_UNKNOWN_WIDTH:
                        case CHANNEL_3MHZ:
                        case CHANNEL_5MHZ:
                        case CHANNEL_10MHZ:
                        case CHANNEL_20MHZ:
                        case CHANNEL_22MHZ:
                        case CHANNEL_30MHZ:
                        case CHANNEL_20_OR_40MHZ:
                            ap_cur->channel_width = CHANNEL_40MHZ;
                            break;
                        default:
                            break;
                    }
                    break;
                case 2: // Reserved
                    break;
                case 3: // Below
                    ap_cur->n_channel.sec_channel = -1;
                    switch (ap_cur->channel_width) {
                        case CHANNEL_UNKNOWN_WIDTH:
                        case CHANNEL_3MHZ:
                        case CHANNEL_5MHZ:
                        case CHANNEL_10MHZ:
                        case CHANNEL_20MHZ:
                        case CHANNEL_22MHZ:
                        case CHANNEL_30MHZ:
                        case CHANNEL_20_OR_40MHZ:
                            ap_cur->channel_width = CHANNEL_40MHZ;
                            break;
                        default:
                            break;
                    }
                    break;
                }
                ap_cur->n_channel.any_chan_width = ((p[3] / 4) % 2);
            }

            // HT capabilities
            if (p[0] == 0x2d && p[1] > 18) {
                if (ap_cur->standard[0] == '\0')
                    ap_cur->standard[0] = 'n';

                // Short GI for 20/40MHz
                ap_cur->n_channel.short_gi_20 = (p[3] / 32) % 2;
                ap_cur->n_channel.short_gi_40 = (p[3] / 64) % 2;

                // Parse MCS rate
                /*
                 * XXX: Sometimes TX and RX spatial stream # differ and none of the beacon
                 * have that. If someone happens to have such AP, open an issue with it.
                 * Ref: https://www.wireshark.org/lists/wireshark-bugs/201307/msg00098.html
                 * See IEEE standard 802.11-2012 table 8.126
                 *
                 * For now, just figure out the highest MCS rate.
                 */
                if (-1 == ap_cur->n_channel.mcs_index) {
                    uint32_t rx_mcs_bitmask = 0;
                    memcpy(&rx_mcs_bitmask, p + 5, sizeof(uint32_t));
                    while (rx_mcs_bitmask) {
                        ++(ap_cur->n_channel.mcs_index);
                        rx_mcs_bitmask /= 2;
                    }
                }
            }

            // VHT Capabilities
            if (p[0] == 0xbf && p[1] >= 12) {
                // Standard is AC
                strcpy(ap_cur->standard, "ac");

                ap_cur->ac_channel.split_chan = (p[3] / 4) % 4;
                ap_cur->ac_channel.short_gi_80 = (p[3] / 32) % 2;
                ap_cur->ac_channel.short_gi_160 = (p[3] / 64) % 2;
                ap_cur->ac_channel.mu_mimo = ((p[3] / 524288) % 2) || ((p[3] / 1048576) % 2);

                // A few things indicate Wave 2: MU-MIMO, 80+80 Channels
                ap_cur->ac_channel.wave_2 = ap_cur->ac_channel.mu_mimo || ap_cur->ac_channel.split_chan;
                // Maximum rates (16 bit)
                uint16_t tx_mcs = 0;
                memcpy(&tx_mcs, p + 10, sizeof(uint16_t));

                // Maximum of 8 SS, each uses 2 bits
                for (uint8_t stream_idx = 0; stream_idx < MAX_AC_MCS_INDEX; ++stream_idx) {
                    uint8_t mcs = (uint8_t)(tx_mcs % 4);

                    // Unsupported -> No more spatial stream
                    if (mcs == 3)
                        break;

                    switch (mcs) {
                    case 0: // support of MCS 0-7
                        ap_cur->ac_channel.mcs_index[stream_idx] = 7;
                        break;
                    case 1: // support of MCS 0-8
                        ap_cur->ac_channel.mcs_index[stream_idx] = 8;
                        break;
                    case 2: // support of MCS 0-9
                        ap_cur->ac_channel.mcs_index[stream_idx] = 9;
                        break;
                    }

                    // Next spatial stream
                    tx_mcs /= 4;
                }
            }

            // VHT Operations
            if (p[0] == 0xc0 && p[1] >= 3) {
                // Standard is AC
                strcpy(ap_cur->standard, "ac");

                // Channel width
                switch (p[2]) {
                case 0: // 20 or 40MHz
                    ap_cur->channel_width = CHANNEL_20_OR_40MHZ;
                    break;
                case 1:
                    ap_cur->channel_width = CHANNEL_80MHZ;
                    break;
                case 2:
                    ap_cur->channel_width = CHANNEL_160MHZ;
                    break;
                case 3: // 80+80MHz
                    ap_cur->channel_width = CHANNEL_80_80MHZ;
                    ap_cur->ac_channel.split_chan = 1;
                    break;
                }

                // 802.11ac channel center segments
                ap_cur->ac_channel.center_sgmt[0] = p[3];
                ap_cur->ac_channel.center_sgmt[1] = p[4];
            }

            p += 2 + p[1];
        }

        // Now get max rate
        if (ap_cur->standard[0] == 'n' || strcmp(ap_cur->standard, "ac") == 0) {
            int sgi = 0;
            int width = 0;

            switch (ap_cur->channel_width) {
                case CHANNEL_20MHZ:
                    width = 20;
                    sgi = ap_cur->n_channel.short_gi_20;
                    break;
                case CHANNEL_20_OR_40MHZ:
                case CHANNEL_40MHZ:
                    width = 40;
                    sgi = ap_cur->n_channel.short_gi_40;
                    break;
                case CHANNEL_80MHZ:
                    width = 80;
                    sgi = ap_cur->ac_channel.short_gi_80;
                    break;
                case CHANNEL_80_80MHZ:
                case CHANNEL_160MHZ:
                    width = 160;
                    sgi = ap_cur->ac_channel.short_gi_160;
                    break;
                default:
                    break;
            }

            if (width != 0) {
                // In case of ac, get the amount of spatial streams
                int amount_ss = 1;
                if (ap_cur->standard[0] != 'n')
                {
                    for (amount_ss = 0; amount_ss < MAX_AC_MCS_INDEX && ap_cur->ac_channel.mcs_index[amount_ss] != 0; ++amount_ss)
                        ;
                }

                // Get rate
                float max_rate = (ap_cur->standard[0] == 'n')
                        ? get_80211n_rate(width, sgi, ap_cur->n_channel.mcs_index)
                        : get_80211ac_rate(width, sgi,ap_cur->ac_channel.mcs_index[amount_ss - 1], amount_ss);

                // If no error, update rate
                if (max_rate > 0)
                    ap_cur->max_speed = (int) max_rate;
            }
        }
    }

    /* packet parsing: Beacon & Probe response */
    /* TODO: Merge this if and the one above */
    if ((buf[0] == 0x80 || buf[0] == 0x50) && caplen > 38) {
        p = buf + 36; //ignore hdr + fixed params

        while (p < buf + caplen) {
            type = p[0];
            length = p[1];
            if (p + 2 + length > buf + caplen)
                break;

            // Find WPA and RSN tags
            if ((type == 0xDD && (length >= 8) && (memcmp(p + 2, "\x00\x50\xF2\x01\x01\x00", 6) == 0)) || (type == 0x30)) {
                ap_cur->security &= ~(STD_WEP | ENC_WEP | STD_WPA);

                org_p = p;
                offset = 0;

                if (type == 0xDD) {
                    //WPA defined in vendor specific tag -> WPA1 support
                    ap_cur->security |= STD_WPA;
                    offset = 4;
                }

                // RSN => WPA2
                if (type == 0x30) {
                    ap_cur->security |= STD_WPA2;
                    offset = 0;
                }

                if (length < (18 + offset)) {
                    p += length + 2;
                    continue;
                }

                // Number of pairwise cipher suites
                if (p + 9 + offset > buf + caplen)
                    break;
                numuni = p[8 + offset] + (p[9 + offset] << 8);

                // Number of Authentication Key Managament suites
                if (p + (11 + offset) + 4 * numuni > buf + caplen)
                    break;
                numauth = p[(10 + offset) + 4 * numuni] + (p[(11 + offset) + 4 * numuni] << 8);

                p += (10 + offset);

                if (type != 0x30) {
                    if (p + (4 * numuni) + (2 + 4 * numauth) > buf + caplen)
                        break;
                } else {
                    if (p + (4 * numuni) + (2 + 4 * numauth) + 2 > buf + caplen)
                        break;
                }

                // Get the list of cipher suites
                for (i = 0; i < numuni; i++) {
                    switch (p[i * 4 + 3]) {
                    case 0x01:
                        ap_cur->security |= ENC_WEP;
                        break;
                    case 0x02:
                        ap_cur->security |= ENC_TKIP;
                        break;
                    case 0x03:
                        ap_cur->security |= ENC_WRAP;
                        break;
                    case 0x0A:
                    case 0x04:
                        ap_cur->security |= ENC_CCMP;
                        break;
                    case 0x05:
                        ap_cur->security |= ENC_WEP104;
                        break;
                    case 0x08:
                    case 0x09:
                        ap_cur->security |= ENC_GCMP;
                        break;
                    default:
                        break;
                    }
                }

                p += 2 + 4 * numuni;

                // Get the AKM suites
                for (i = 0; i < numauth; i++) {
                    switch (p[i * 4 + 3]) {
                    case 0x01:
                        ap_cur->security |= AUTH_MGT;
                        break;
                    case 0x02:
                        ap_cur->security |= AUTH_PSK;
                        break;
                    default:
                        break;
                    }
                }

                p += 2 + 4 * numauth;

                if (type == 0x30)
                    p += 2;

                p = org_p + length + 2;
            } else if ((type == 0xDD && (length >= 8) && (memcmp(p + 2, "\x00\x50\xF2\x02\x01\x01", 6) == 0))) {
                 // QoS IE
                 ap_cur->security |= STD_QOS;
                 p += length + 2;
            } else if ((type == 0xDD && (length >= 4) && (memcmp(p + 2, "\x00\x50\xF2\x04", 4) == 0))) {
                // WPS IE
                org_p = p;
                p += 6;
                int len = length, subtype = 0, sublen = 0;
                while (len >= 4) {
                    subtype = (p[0] << 8) + p[1];
                    sublen = (p[2] << 8) + p[3];
                    if (sublen > len) break;
                    switch (subtype)
                    {
                        case 0x104a: // WPS Version
                            ap_cur->wps.version = p[4];
                            break;
                        case 0x1011: // Device Name
                        case 0x1012: // Device Password ID
                        case 0x1021: // Manufacturer
                        case 0x1023: // Model
                        case 0x1024: // Model Number
                        case 0x103b: // Response Type
                        case 0x103c: // RF Bands
                        case 0x1041: // Selected Registrar
                        case 0x1042: // Serial Number
                            break;
                        case 0x1044: // WPS State
                            ap_cur->wps.state = p[4];
                            break;
                        case 0x1047: // UUID Enrollee
                        case 0x1049: // Vendor Extension
                            if (memcmp(&p[4], "\x00\x37\x2A", 3) == 0) {
                                unsigned char *pwfa = &p[7];
                                int wfa_len = ntohs(*((short *) &p[2]));
                                while (wfa_len > 0) {
                                    if (*pwfa == 0) { // Version2
                                        ap_cur->wps.version = pwfa[2];
                                        break;
                                    }
                                    wfa_len -= pwfa[1] + 2;
                                    pwfa += pwfa[1] + 2;
                                }
                            }
                            break;
                        case 0x1054: // Primary Device Type
                            break;
                        case 0x1057: // AP Setup Locked
                            ap_cur->wps.ap_setup_locked = p[4];
                            break;
                        case 0x1008: // Config Methods
                        case 0x1053: // Selected Registrar Config Methods
                            ap_cur->wps.meth = (p[4] << 8) + p[5];
                            break;
                        default: // Unknown type-length-value
                            break;
                    }
                    p += sublen + 4;
                    len -= sublen + 4;
                }
                p = org_p + length + 2;
            } else {
                p += length + 2;
            }
        }
    }

    /* packet parsing: Authentication Response */
    if (buf[0] == 0xB0 && caplen >= 30) {
        if (ap_cur->security & STD_WEP) {
            //successful step 2 or 4 (coming from the AP)
            if (memcmp(buf + 28, "\x00\x00", 2) == 0 && (buf[26] == 0x02 || buf[26] == 0x04)) {
                ap_cur->security &= ~(AUTH_OPN | AUTH_PSK | AUTH_MGT);
                if (buf[24] == 0x00)
                    ap_cur->security |= AUTH_OPN;
                if (buf[24] == 0x01)
                    ap_cur->security |= AUTH_PSK;
            }
        }
    }

    /* packet parsing: Association Request */
    if (buf[0] == 0x00 && caplen > 28) {
        p = buf + 28;

        while (p < buf + caplen) {
            if (p + 2 + p[1] > buf + caplen)
                break;

            if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0' && (p[1] > 1 || p[2] != ' ')) {
                /* found a non-cloaked ESSID */
                n = (p[1] > 32) ? 32 : p[1];

                memset(ap_cur->essid, 0, 33);
                memcpy(ap_cur->essid, p + 2, n);
                ap_cur->ssid_length = n;

                // todo: store ivs file
            }

            p += 2 + p[1];
        }
        if (st_cur != NULL)
            st_cur->wpa.state = 0;
    }

    // packet parsing: some data
    if ((buf[0] & 0x0C) == 0x08) {
        // todo: update the channel if we didn't get any beacon

        // check the SNAP header to see if data is encrypted
        z = ((buf[1] & 3) != 3) ? 24 : 30;

        /* Check if 802.11e (QoS) */

        if (24 == z) {
            // todo: list_check_decloak
            printf(">>> z == 24\n");
        }

        if (z + 26 > (unsigned) caplen)
            goto write_packet;

        if (buf[z] == buf[z + 1] && buf[z + 2] == 0x03)
        {
            //            if( ap_cur->encryption < 0 )
            //                ap_cur->encryption = 0;

            // if ethertype == IPv4, find the LAN address

            if (buf[z + 6] == 0x08 && buf[z + 7] == 0x00 && (buf[1] & 3) == 0x01)
                memcpy(ap_cur->lanip, &buf[z + 20], 4);

            if (buf[z + 6] == 0x08 && buf[z + 7] == 0x06)
                memcpy(ap_cur->lanip, &buf[z + 22], 4);
        }

        if (ap_cur->security == 0 || (ap_cur->security & STD_WEP)) {
            if ((buf[1] & 0x40) != 0x40) {
                ap_cur->security |= STD_OPN;
            } else {
                if ((buf[z + 3] & 0x20) == 0x20) {
                    ap_cur->security |= STD_WPA;
                } else {
                    ap_cur->security |= STD_WEP;
                    if ((buf[z + 3] & 0xC0) != 0x00) {
                        ap_cur->security |= ENC_WEP40;
                    } else {
                        ap_cur->security &= ~ENC_WEP40;
                        ap_cur->security |= ENC_WEP;
                    }
                }
            }
        }

        if (z + 10 > (unsigned) caplen)
            goto write_packet;

        if (ap_cur->security & STD_WEP) {
            /* WEP: check if we've already seen this IV */
            if (!uniqueiv_check(ap_cur->uiv_root, &buf[z])) {
                /* first time seen IVs */

                // if (G.f_ivs != NULL)

                uniqueiv_mark(ap_cur->uiv_root, &buf[z]);
                ap_cur->nb_data++;
            }

            // Record all data linked to IV to detect WEP Cloaking
            // if (G.f_ivs == NULL && G.detect_anomaly)
        } else {
            ap_cur->nb_data++;
        }

        z = ((buf[1] & 3) != 3) ? 24 : 30;

        /* Check if 802.11e (QoS) */
        if ((buf[0] & 0x80) == 0x80)
            z += 2;
        if (z + 26 > (unsigned) caplen)
            goto write_packet;
        z += 6; //skip LLC header

        /* check ethertype == EAPOL */
        if (buf[z] == 0x88 && buf[z + 1] == 0x8E && (buf[1] & 0x40) != 0x40) {
            ap_cur->EAP_detected = 1;

            z += 2; //skip ethertype

            if (st_cur == NULL)
                goto write_packet;

            /* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */
            if ((buf[z + 6] & 0x08) != 0 && (buf[z + 6] & 0x40) == 0
             && (buf[z + 6] & 0x80) != 0 && (buf[z + 5] & 0x01) == 0) {
                memcpy(st_cur->wpa.anonce, &buf[z + 17], 32);
                st_cur->wpa.state = 1;
            }
            /* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */
            if (z + 17 + 32 > (unsigned) caplen)
                goto write_packet;
            if ((buf[z + 6] & 0x08) != 0 && (buf[z + 6] & 0x40) == 0
             && (buf[z + 6] & 0x80) == 0 && (buf[z + 5] & 0x01) != 0) {
                if (memcmp(&buf[z + 17], ZERO, 32) != 0) {
                    memcpy(st_cur->wpa.snonce, &buf[z + 17], 32);
                    st_cur->wpa.state |= 2;
                }

                if ((st_cur->wpa.state & 4) != 4) {
                    st_cur->wpa.eapol_size = (buf[z + 2] << 8) + buf[z + 3] + 4;

                    if ((caplen - z < st_cur->wpa.eapol_size) || (st_cur->wpa.eapol_size == 0)
                     || (caplen - z < 81 + 16) || (st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol))) {
                        // Ignore the packet trying to crash us.
                        st_cur->wpa.eapol_size = 0;
                        goto write_packet;
                    }

                    memcpy(st_cur->wpa.keymic, &buf[z + 81], 16);
                    memcpy( st_cur->wpa.eapol, &buf[z], st_cur->wpa.eapol_size);
                    memset(st_cur->wpa.eapol + 81, 0, 16);
                    st_cur->wpa.state |= 4;
                    st_cur->wpa.keyver = buf[z + 6] & 7;
                }
            }
            /* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */
            if ((buf[z + 6] & 0x08) != 0 && (buf[z + 6] & 0x40) != 0
             && (buf[z + 6] & 0x80) != 0 && (buf[z + 5] & 0x01) != 0) {
                if (memcmp(&buf[z + 17], ZERO, 32) != 0) {
                    memcpy(st_cur->wpa.anonce, &buf[z + 17], 32);
                    st_cur->wpa.state |= 1;
                }

                if ((st_cur->wpa.state & 4) != 4) {
                    st_cur->wpa.eapol_size = (buf[z + 2] << 8) + buf[z + 3] + 4;

                    if ((caplen - (unsigned) z < st_cur->wpa.eapol_size) || (st_cur->wpa.eapol_size == 0)
                     || (caplen - (unsigned) z < 81 + 16) || (st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol)))
                    {
                        // Ignore the packet trying to crash us.
                        st_cur->wpa.eapol_size = 0;
                        goto write_packet;
                    }

                    memcpy(st_cur->wpa.keymic, &buf[z + 81], 16);
                    memcpy(st_cur->wpa.eapol, &buf[z], st_cur->wpa.eapol_size);
                    memset(st_cur->wpa.eapol + 81, 0, 16);
                    st_cur->wpa.state |= 4;
                    st_cur->wpa.keyver = buf[z + 6] & 7;
                }
            }

            if (st_cur->wpa.state == 7) {
                memcpy(st_cur->wpa.stmac, st_cur->stmac, 6);
                memcpy(wpa_bssid, ap_cur->bssid, 6);
                memset(this->message, '\x00', sizeof(this->message));
                printf("WPA handshake: %02X:%02X:%02X:%02X:%02X:%02X\n",
                       wpa_bssid[0], wpa_bssid[1], wpa_bssid[2], wpa_bssid[3], wpa_bssid[4], wpa_bssid[5]);

                // if (G.f_ivs != NULL)
            }

        }
    }

write_packet:
    if (f_cap != NULL && caplen >= 10) {

        gettimeofday(&tv, NULL);

        pkh.caplen = pkh.len = caplen;
        pkh.tv_sec = tv.tv_sec;
        pkh.tv_usec = (tv.tv_usec & ~0x1ff) + ri->ri_power + 64;

        n = sizeof(pkh);
        if (fwrite(&pkh, 1, n, f_cap) != (size_t) n)
            throw "fwrite(packet header) failed";
        fflush(stdout);

        n = pkh.caplen;
        if (fwrite(buf, 1, n, f_cap) != (size_t) n)
            perror("fwrite(packet data) failed");
        fflush(stdout);
    }

    return 0;
}







