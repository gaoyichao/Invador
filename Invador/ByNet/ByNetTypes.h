#ifndef BYNETTYPES_H
#define BYNETTYPES_H

#include <nl80211.h>
#include <iw.h>

#include <pcap.h>
#include <eapol.h>

#include <string>
#include <vector>
#include <map>

enum driver_type {
    DT_NULL = 0,
    DT_WLANNG,
    DT_HOSTAP,
    DT_MADWIFI,
    DT_MADWIFING,
    DT_BCM43XX,
    DT_ORINOCO,
    DT_ZD1211RW,
    DT_ACX,
    DT_MAC80211_RT,
    DT_AT76USB,
    DT_IPW2200
};

struct rx_info
{
    uint64_t ri_mactime;
    int32_t ri_power;
    int32_t ri_noise;
    uint32_t ri_channel;
    uint32_t ri_freq;
    uint32_t ri_rate;
    uint32_t ri_antenna;
}  __attribute__((packed));


/* some constants */

#define REFRESH_RATE 100000 /* default delay in us between updates */
#define DEFAULT_HOPFREQ 250 /* default delay in ms between channel hopping */
#define DEFAULT_CWIDTH 20 /* 20 MHz channels by default */

#define NB_PWR 5 /* size of signal power ring buffer */
#define NB_PRB 10 /* size of probed ESSID ring buffer */

#define MAX_CARDS 8 /* maximum number of cards to capture from */

#define STD_OPN 0x0001
#define STD_WEP 0x0002
#define STD_WPA 0x0004
#define STD_WPA2 0x0008

#define STD_FIELD (STD_OPN | STD_WEP | STD_WPA | STD_WPA2)

#define ENC_WEP 0x0010
#define ENC_TKIP 0x0020
#define ENC_WRAP 0x0040
#define ENC_CCMP 0x0080
#define ENC_WEP40 0x1000
#define ENC_WEP104 0x0100
#define ENC_GCMP 0x4000

#define ENC_FIELD                                                              \
    (ENC_WEP | ENC_TKIP | ENC_WRAP | ENC_CCMP | ENC_WEP40 | ENC_WEP104 | ENC_GCMP)

#define AUTH_OPN 0x0200
#define AUTH_PSK 0x0400
#define AUTH_MGT 0x0800

#define AUTH_FIELD (AUTH_OPN | AUTH_PSK | AUTH_MGT)

#define STD_QOS 0x2000

#define QLT_TIME 5
#define QLT_COUNT 25

#define SORT_BY_NOTHING 0
#define SORT_BY_BSSID 1
#define SORT_BY_POWER 2
#define SORT_BY_BEACON 3
#define SORT_BY_DATA 4
#define SORT_BY_PRATE 5
#define SORT_BY_CHAN 6
#define SORT_BY_MBIT 7
#define SORT_BY_ENC 8
#define SORT_BY_CIPHER 9
#define SORT_BY_AUTH 10
#define SORT_BY_ESSID 11
#define MAX_SORT 11

#define RATES "\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"

#define PROBE_REQ                                                              \
    "\x40\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC"         \
    "\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"

//milliseconds to store last packets
#define BUFFER_TIME 3000

/* WPS_info struct */
struct WPS_info
{
    unsigned char version; /* WPS Version */
    unsigned char state; /* Current WPS state */
    unsigned char ap_setup_locked; /* AP setup locked */
    unsigned int meth; /* WPS Config Methods */
};

#define MAX_AC_MCS_INDEX 8

/* 802.11n channel information */
struct n_channel_info
{
    char mcs_index; /* Maximum MCS TX index     */
    char sec_channel; /* 802.11n secondary channel*/
    unsigned char short_gi_20; /* Short GI for 20MHz       */
    unsigned char short_gi_40; /* Short GI for 40MHz       */
    unsigned char any_chan_width; /* Support for 20 or 40MHz
                                    as opposed to only 20 or
                                    only 40MHz               */
};

/* 802.11ac channel information */
struct ac_channel_info
{
    unsigned char center_sgmt[2];
    /* 802.11ac Center segment 0*/
    unsigned char mu_mimo; /* MU-MIMO support          */
    unsigned char short_gi_80; /* Short GI for 80MHz       */
    unsigned char short_gi_160; /* Short GI for 160MHz      */
    unsigned char split_chan; /* 80+80MHz Channel support */
    unsigned char mhz_160_chan; /* 160 MHz channel support  */
    unsigned char wave_2; /* Wave 2                   */
    unsigned char mcs_index[MAX_AC_MCS_INDEX];
    /* Maximum TX rate          */
};

enum channel_width_enum
{
    CHANNEL_UNKNOWN_WIDTH,
    CHANNEL_3MHZ,
    CHANNEL_5MHZ,
    CHANNEL_10MHZ,
    CHANNEL_20MHZ,
    CHANNEL_22MHZ,
    CHANNEL_30MHZ,
    CHANNEL_20_OR_40MHZ,
    CHANNEL_40MHZ,
    CHANNEL_80MHZ,
    CHANNEL_80_80MHZ,
    CHANNEL_160MHZ
};

/* linked list of detected clients */
class ByNetApInfo;
class ByNetStInfo;

/* linked list of detected macs through ack, cts or rts frames */

struct NA_info
{
    struct NA_info *prev; /* the prev client in list   */
    struct NA_info *next; /* the next client in list   */
    time_t tinit, tlast; /* first and last time seen  */
    unsigned char namac[6]; /* the stations MAC address  */
    int power; /* last signal power         */
    int channel; /* captured on channel       */
    int ack; /* number of ACK frames      */
    int ack_old; /* old number of ACK frames  */
    int ackps; /* number of ACK frames/s    */
    int cts; /* number of CTS frames      */
    int rts_r; /* number of RTS frames (rx) */
    int rts_t; /* number of RTS frames (tx) */
    int other; /* number of other frames    */
    struct timeval tv; /* time for ack per second   */
};



#endif // BYNETTYPES_H
