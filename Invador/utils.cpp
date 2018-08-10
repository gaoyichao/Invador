
#include <nl80211.h>
#include <iw.h>

#include <ByNetEngine.h>

#include <thread>
#include <stdio.h>


void print_ssid_escaped(const uint8_t len, const uint8_t *data)
{
    int i;

    for (i = 0; i < len; i++) {
        if (isprint(data[i]) && data[i] != ' ' && data[i] != '\\')
            printf("%c", data[i]);
        else if (data[i] == ' ' &&  (i != 0 && i != len -1))
            printf(" ");
        else
            printf("\\x%.2x", data[i]);
    }
}

static const char *ifmodes[NL80211_IFTYPE_MAX + 1] = {
    "unspecified",
    "IBSS",
    "managed",
    "AP",
    "AP/VLAN",
    "WDS",
    "monitor",
    "mesh point",
    "P2P-client",
    "P2P-GO",
    "P2P-device",
    "outside context of a BSS",
    "NAN",
};

static char modebuf[100];

const char *iftype_name(enum nl80211_iftype iftype)
{
    if (iftype <= NL80211_IFTYPE_MAX && ifmodes[iftype])
        return ifmodes[iftype];
    sprintf(modebuf, "Unknown mode (%d)", iftype);
     return modebuf;
}


int ieee80211_frequency_to_channel(int freq)
{
    /* see 802.11-2007 17.3.8.3.2 and Annex J */
    if (freq == 2484)
        return 14;
    else if (freq < 2484)
        return (freq - 2407) / 5;
    else if (freq >= 4910 && freq <= 4980)
        return (freq - 4000) / 5;
    else if (freq <= 45000) /* DMG band lower limit */
        return (freq - 5000) / 5;
    else if (freq >= 58320 && freq <= 64800)
        return (freq - 56160) / 2160;
    else
        return 0;
}


const char *channel_width_name(enum nl80211_chan_width width)
{
    switch (width) {
    case NL80211_CHAN_WIDTH_20_NOHT:
        return "20 MHz (no HT)";
    case NL80211_CHAN_WIDTH_20:
        return "20 MHz";
    case NL80211_CHAN_WIDTH_40:
        return "40 MHz";
    case NL80211_CHAN_WIDTH_80:
        return "80 MHz";
    case NL80211_CHAN_WIDTH_80P80:
        return "80+80 MHz";
    case NL80211_CHAN_WIDTH_160:
        return "160 MHz";
    case NL80211_CHAN_WIDTH_5:
        return "5 MHz";
    case NL80211_CHAN_WIDTH_10:
        return "10 MHz";
    default:
        return "unknown";
    }
}

const char *cipher_name(__u32 c)
{
    static char buf[20];

    switch (c) {
    case 0x000fac01:
        return "WEP40 (00-0f-ac:1)";
    case 0x000fac05:
        return "WEP104 (00-0f-ac:5)";
    case 0x000fac02:
        return "TKIP (00-0f-ac:2)";
    case 0x000fac04:
        return "CCMP-128 (00-0f-ac:4)";
    case 0x000fac06:
        return "CMAC (00-0f-ac:6)";
    case 0x000fac08:
        return "GCMP-128 (00-0f-ac:8)";
    case 0x000fac09:
        return "GCMP-256 (00-0f-ac:9)";
    case 0x000fac0a:
        return "CCMP-256 (00-0f-ac:10)";
    case 0x000fac0b:
        return "GMAC-128 (00-0f-ac:11)";
    case 0x000fac0c:
        return "GMAC-256 (00-0f-ac:12)";
    case 0x000fac0d:
        return "CMAC-256 (00-0f-ac:13)";
    case 0x00147201:
        return "WPI-SMS4 (00-14-72:1)";
    default:
        sprintf(buf, "%.2x-%.2x-%.2x:%d",
            c >> 24, (c >> 16) & 0xff,
            (c >> 8) & 0xff, c & 0xff);

        return buf;
    }
}

