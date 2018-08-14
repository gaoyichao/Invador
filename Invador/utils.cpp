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


/*
int print_iface_handler(struct nl_msg *msg, void *arg)
{
    std::cout << ">>> iface" << std::endl;

    struct genlmsghdr *gnlh = (struct genlmsghdr*)nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    QStandardItemModel *model = (QStandardItemModel*)arg;

    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    QStandardItem *itemProject = new QStandardItem("Phy#");
    if (tb_msg[NL80211_ATTR_WIPHY]) {
        itemProject->setText(QString("Phy#") + QString::number(nla_get_u32(tb_msg[NL80211_ATTR_WIPHY])));
        model->appendRow(itemProject);
        model->setItem(model->indexFromItem(itemProject).row(), 1, new QStandardItem(QStringLiteral("无线网卡")));
    } else {
        return NL_SKIP;
    }

    if (tb_msg[NL80211_ATTR_IFNAME]) {
        QStandardItem *itemChild = new QStandardItem("Interface");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(nla_get_string(tb_msg[NL80211_ATTR_IFNAME])));
    }

    if (tb_msg[NL80211_ATTR_IFINDEX]) {
        QStandardItem *itemChild = new QStandardItem("ifindex");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(nla_get_u32(tb_msg[NL80211_ATTR_IFINDEX]))));
    }

    if (tb_msg[NL80211_ATTR_WDEV]) {
        QStandardItem *itemChild = new QStandardItem("wdev");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(nla_get_u64(tb_msg[NL80211_ATTR_WDEV]))));
    }

    if (tb_msg[NL80211_ATTR_MAC]) {
        uint8_t *mac = (uint8_t*)nla_data(tb_msg[NL80211_ATTR_MAC]);
        char macstr[18];
        sprintf(macstr, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        QStandardItem *itemChild = new QStandardItem("物理地址");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString(macstr)));
    }

    if (tb_msg[NL80211_ATTR_SSID]) {
        int len = nla_len(tb_msg[NL80211_ATTR_SSID]);
        len = (len < 32) ? len : 32;
        uint8_t *ssid = (uint8_t*)nla_data(tb_msg[NL80211_ATTR_SSID]);
        char ssidstr[128];

        for (int i = 0; i < len; i++) {
            if (isprint(ssid[i]) && ssid[i] != ' ' && ssid[i] != '\\')
                sprintf(ssidstr, "%c", ssid[i]);
            else if (ssid[i] == ' ' &&  (i != 0 && i != len -1))
                sprintf(ssidstr, " ");
            else
                sprintf(ssidstr, "\\x%.2x", ssid[i]);
        }
        QStandardItem *itemChild = new QStandardItem("ssid");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString(ssidstr)));
    }

    if (tb_msg[NL80211_ATTR_IFTYPE]) {
        enum nl80211_iftype type = (enum nl80211_iftype)nla_get_u32(tb_msg[NL80211_ATTR_IFTYPE]);

        QStandardItem *itemChild = new QStandardItem("工作模式");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(iftype_name(type)));
    }

    if (tb_msg[NL80211_ATTR_WIPHY_FREQ]) {
        uint32_t freq = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FREQ]);
        int channel = ieee80211_frequency_to_channel(freq);

        QStandardItem *itemChild = new QStandardItem("频道");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(channel)));

        itemChild = new QStandardItem("频率");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(freq) + " MHz"));

        if (tb_msg[NL80211_ATTR_CHANNEL_WIDTH]) {
            itemChild = new QStandardItem("带宽");
            itemProject->appendRow(itemChild);
            itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(channel_width_name((enum nl80211_chan_width)nla_get_u32(tb_msg[NL80211_ATTR_CHANNEL_WIDTH]))));
        }

        if (tb_msg[NL80211_ATTR_CENTER_FREQ1]) {
            uint32_t cfreq1 = nla_get_u32(tb_msg[NL80211_ATTR_CENTER_FREQ1]);
            itemChild = new QStandardItem("Freq Center 1");
            itemProject->appendRow(itemChild);
            itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(cfreq1) + " MHz"));
        }

        if (tb_msg[NL80211_ATTR_CENTER_FREQ2]) {
            uint32_t cfreq2 = nla_get_u32(tb_msg[NL80211_ATTR_CENTER_FREQ2]);
            itemChild = new QStandardItem("Freq Center 2");
            itemProject->appendRow(itemChild);
            itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(cfreq2) + " MHz"));
        }
    }

    if (tb_msg[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]) {
        uint32_t txpow = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]);
        QStandardItem *itemChild = new QStandardItem("txpower");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(txpow / 100)+"."+QString::number(txpow % 100)+" dBm"));
    }

    if (tb_msg[NL80211_ATTR_WIPHY]) {
        QStandardItem *itemChild = new QStandardItem("wiphy");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]))));
    }

    return NL_SKIP;
}
*/


