#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QStandardItem>

#include <ByNetEngine.h>
#include <ByNetDev.h>

#include <iostream>
#include <thread>
#include <map>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

BYNetEngine engine;

int print_iface_handler(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = (struct genlmsghdr*)nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    std::map<__u32, ByNetDev> *devs = (std::map<__u32, ByNetDev> *)arg;

    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    ByNetDev *dev;
    if (tb_msg[NL80211_ATTR_WIPHY]) {
        __u32 phyid = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
        auto it = devs->find(phyid);
        if (it != devs->end()) {
            dev = &(it->second);
        } else {
            (*devs)[phyid] = ByNetDev();
            dev = &((*devs)[phyid]);
        }
        dev->SetPhyIndex(phyid);
    } else {
        return NL_SKIP;
    }

    ByNetInterface *interface;
    if (tb_msg[NL80211_ATTR_IFINDEX]) {
        __u32 ifidx = nla_get_u32(tb_msg[NL80211_ATTR_IFINDEX]);
        interface = dev->GetInterface(ifidx);
        if (NULL == interface)
            interface = dev->AddInterface(ifidx);
        interface->SetIfIndex(ifidx);
    } else {
        return NL_SKIP;
    }


    if (tb_msg[NL80211_ATTR_IFNAME]) {
        interface->SetIfName(nla_get_string(tb_msg[NL80211_ATTR_IFNAME]));
    } else {
        return NL_SKIP;
    }

    if (tb_msg[NL80211_ATTR_WDEV])
        interface->SetWDev(nla_get_u64(tb_msg[NL80211_ATTR_WDEV]));

    if (tb_msg[NL80211_ATTR_MAC])
        interface->SetMac((uint8_t*)nla_data(tb_msg[NL80211_ATTR_MAC]));

    if (tb_msg[NL80211_ATTR_SSID])
        interface->SetSSID((uint8_t*)nla_data(tb_msg[NL80211_ATTR_SSID]), nla_len(tb_msg[NL80211_ATTR_SSID]));

    if (tb_msg[NL80211_ATTR_IFTYPE])
        interface->SetIfType((enum nl80211_iftype)nla_get_u32(tb_msg[NL80211_ATTR_IFTYPE]));

    if (tb_msg[NL80211_ATTR_WIPHY_FREQ]) {
        interface->SetFreq(nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FREQ]));
        if (tb_msg[NL80211_ATTR_CHANNEL_WIDTH])
            interface->SetChannelWidth((enum nl80211_chan_width)nla_get_u32(tb_msg[NL80211_ATTR_CHANNEL_WIDTH]));

        if (tb_msg[NL80211_ATTR_CENTER_FREQ1])
            interface->SetCenterFreq1(nla_get_u32(tb_msg[NL80211_ATTR_CENTER_FREQ1]));

        if (tb_msg[NL80211_ATTR_CENTER_FREQ2])
            interface->SetCenterFreq2(nla_get_u32(tb_msg[NL80211_ATTR_CENTER_FREQ2]));
    }

    if (tb_msg[NL80211_ATTR_WIPHY_TX_POWER_LEVEL])
        interface->SetTxPowerLevel(nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]));

    return NL_SKIP;
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

static bool nl80211_has_split_wiphy = false;
int print_feature_handler(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = (struct genlmsghdr*)nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];

    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb_msg[NL80211_ATTR_PROTOCOL_FEATURES]) {
        uint32_t feat = nla_get_u32(tb_msg[NL80211_ATTR_PROTOCOL_FEATURES]);
        if (feat & NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP) {
            nl80211_has_split_wiphy = true;
        }
    }

    return NL_SKIP;
}
/**
 * @ingroup attr
 * Iterate over a stream of nested attributes
 * @arg pos	loop counter, set to current attribute
 * @arg nla	attribute containing the nested attributes
 * @arg rem	initialized to len, holds bytes currently remaining in stream
 */
#define nla_for_each_nested_attr(pos, nla, rem) \
    for (pos = (struct nlattr *)nla_data(nla), rem = nla_len(nla); \
         nla_ok(pos, rem); \
         pos = nla_next(pos, &(rem)))

int _i = 0;
int print_phy_handler(struct nl_msg *msg, void *arg)
{
    std::cout << ">>> haha:" << _i << std::endl;
    _i++;
    /*
     * static variables only work here, other applications need to use the
     * callback pointer and store them there so they can be multithreaded
     * and/or have multiple netlink sockets, etc.
     */
    static int64_t phy_id = -1;


    struct genlmsghdr *gnlh = (struct genlmsghdr*)nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    std::map<__u32, ByNetDev> *devs = (std::map<__u32, ByNetDev> *)arg;
    ByNetDev *dev;
    if (tb_msg[NL80211_ATTR_WIPHY]) {
        phy_id = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
        auto it = devs->find(phy_id);
        if (it != devs->end()) {
            dev = &(it->second);
        } else {
            (*devs)[phy_id] = ByNetDev();
            dev = &((*devs)[phy_id]);
        }
        dev->SetPhyIndex(phy_id);
    } else {
        return NL_SKIP;
    }

    if (tb_msg[NL80211_ATTR_WIPHY_NAME])
        dev->SetPhyName(nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME]));

    if (tb_msg[NL80211_ATTR_MAX_NUM_SCAN_SSIDS])
        dev->SetMaxNumScanSSID(nla_get_u8(tb_msg[NL80211_ATTR_MAX_NUM_SCAN_SSIDS]));

    if (tb_msg[NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS])
        dev->SetMaxNumSchedScanSsid(nla_get_u8(tb_msg[NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS]));

    if (tb_msg[NL80211_ATTR_MAX_SCAN_IE_LEN])
        dev->SetMaxScanIELen(nla_get_u16(tb_msg[NL80211_ATTR_MAX_SCAN_IE_LEN]));

    if (tb_msg[NL80211_ATTR_MAX_MATCH_SETS])
        dev->SetMaxMatchSets(nla_get_u16(tb_msg[NL80211_ATTR_MAX_MATCH_SETS]));

    if (tb_msg[NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS])
        dev->SetMaxNumSchedScanPlans(nla_get_u32(tb_msg[NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS]));

    if (tb_msg[NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL])
        dev->SetMaxScanPlanInterval((int)nla_get_u32(tb_msg[NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL]));

    if (tb_msg[NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS])
        dev->SetMaxScanPlanIterations(nla_get_u32(tb_msg[NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS]));

    if (tb_msg[NL80211_ATTR_WIPHY_FRAG_THRESHOLD])
        dev->SetPhyFragThreshold(nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FRAG_THRESHOLD]));

    if (tb_msg[NL80211_ATTR_WIPHY_RTS_THRESHOLD])
        dev->SetPhyRtsThreshold(nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_RTS_THRESHOLD]));

    if (tb_msg[NL80211_ATTR_WIPHY_RETRY_SHORT] || tb_msg[NL80211_ATTR_WIPHY_RETRY_LONG]) {
        dev->SetRetryShort(nla_get_u8(tb_msg[NL80211_ATTR_WIPHY_RETRY_SHORT]));
        dev->SetRetryLong(nla_get_u8(tb_msg[NL80211_ATTR_WIPHY_RETRY_LONG]));
    }

    if (tb_msg[NL80211_ATTR_WIPHY_COVERAGE_CLASS])
        dev->SetCoverageClass(nla_get_u8(tb_msg[NL80211_ATTR_WIPHY_COVERAGE_CLASS]));

    if (tb_msg[NL80211_ATTR_CIPHER_SUITES]) {
        int num = nla_len(tb_msg[NL80211_ATTR_CIPHER_SUITES]) / sizeof(__u32);
        __u32 *ciphers = (__u32 *)nla_data(tb_msg[NL80211_ATTR_CIPHER_SUITES]);
        dev->SetSupportedCiphers(ciphers, num);
    }

    struct nlattr *nl_mode;
    int rem_mode;
    if (tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES]) {
        dev->ClearSupportedIfType();
        nla_for_each_nested_attr(nl_mode, tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES], rem_mode)
            dev->AddSupportedIfType((enum nl80211_iftype)nla_type(nl_mode));
    }

    if (tb_msg[NL80211_ATTR_SOFTWARE_IFTYPES]) {
        dev->ClearSoftwareIfType();
        nla_for_each_nested_attr(nl_mode, tb_msg[NL80211_ATTR_SOFTWARE_IFTYPES], rem_mode)
            dev->AddSoftwareIfType((enum nl80211_iftype)nla_type(nl_mode));
    }

    struct nlattr *nl_cmd;
    int rem_cmd;
    if (tb_msg[NL80211_ATTR_SUPPORTED_COMMANDS]) {
        dev->ClearSupportedCmd();
        nla_for_each_nested_attr(nl_cmd, tb_msg[NL80211_ATTR_SUPPORTED_COMMANDS], rem_cmd)
            dev->AddSupportedCmd((enum nl80211_commands)nla_get_u32(nl_cmd));
    }

    return NL_SKIP;
}

int handle_dev_dump(BYNetEngine *engine, struct nl_msg *msg, void *arg)
{
    register_handler(print_iface_handler, arg);
    return 0;
}

int handle_feature(BYNetEngine *engine, struct nl_msg *msg, void *arg)
{
    register_handler(print_feature_handler, NULL);
    return 0;
}

int handle_info(BYNetEngine *engine, struct nl_msg *msg, void *arg)
{
    engine->handle_cmd(0, NL80211_CMD_GET_PROTOCOL_FEATURES, handle_feature, NULL);
    if (nl80211_has_split_wiphy) {
        nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
        nlmsg_hdr(msg)->nlmsg_flags |= NLM_F_DUMP;
    }

    register_handler(print_phy_handler, arg);

    return 0;
}

int handle_interface_add(BYNetEngine *engine, struct nl_msg *msg, void *arg)
{
    std::cout << ">>> add interface 0" << std::endl;
    NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, "moni0");
    NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);
    return 0;
nla_put_failure:
    return -ENOBUFS;
}

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    m_devs.clear();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_mDevPushButton_clicked()
{
    m_devs.clear();
    engine.handle_cmd(NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, handle_dev_dump, &m_devs);

    std::cout << ">>> " << std::endl;
    std::cout << ">>> num of devs:" << m_devs.size() << std::endl;
    for (auto it = m_devs.begin(); it != m_devs.end(); it++) {
        ByNetDev *dev = &(it->second);
        auto interfaceMap = dev->GetAllInterfaces();
        std::cout << ">>> num of interfaces:" << interfaceMap.size() << std::endl;
        for (auto infit = interfaceMap.begin(); infit != interfaceMap.end(); infit++) {
            std::cout << ">>> " << infit->second.GetIfName() << std::endl;
        }
    }
}



void MainWindow::on_mDevPushButton_2_clicked()
{
    engine.handle_cmd(NLM_F_DUMP, NL80211_CMD_GET_WIPHY, handle_info, &m_devs);
    std::cout << ">>> " << std::endl;
    std::cout << ">>> num of devs:" << m_devs.size() << std::endl;
    for (auto it = m_devs.begin(); it != m_devs.end(); it++) {
        ByNetDev *dev = &(it->second);
        std::cout << ">>> # supported ciphers:" << dev->GetSupportedCiphers().size() << std::endl;
        std::cout << ">>> # supported if types:" << dev->GetSupportedIfTypes().size() << std::endl;
        std::cout << ">>> # cmd:" << dev->GetSupportedCmd().size() << std::endl;
    }
}

void MainWindow::on_mDevPushButton_3_clicked()
{
    m_devs.clear();
    engine.handle_cmd(NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, handle_dev_dump, &m_devs);
    ByNetInterface const *interface = NULL;
    for (auto it = m_devs.begin(); it != m_devs.end(); it++) {
        ByNetDev *dev = &(it->second);
        interface = dev->FindMonitorInterface();
        if (NULL != interface)
            break;
    }

    if (NULL == interface) {
        std::cout << ">>> add interface" << std::endl;
        engine.prepare(CIB_PHY, 0);
        engine.handle_cmd(0, NL80211_CMD_NEW_INTERFACE, handle_interface_add, NULL);

        m_devs.clear();
        engine.handle_cmd(NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, handle_dev_dump, &m_devs);
        for (auto it = m_devs.begin(); it != m_devs.end(); it++) {
            ByNetDev *dev = &(it->second);
            interface = dev->FindMonitorInterface();
            if (NULL != interface)
                break;
        }
    }

    if (NULL != interface)
        std::cout << ">>> monitor interface:" << interface->GetIfName() << std::endl;
}



