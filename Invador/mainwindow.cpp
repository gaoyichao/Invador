#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QStandardItem>

#include <ByNetEngine.h>

#include <iostream>
#include <thread>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

BYNetEngine engine;

int print_iface_handler(struct nl_msg *msg, void *arg)
{
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

int _i = 0;
int print_phy_handler(struct nl_msg *msg, void *arg)
{
    std::cout << ">>> haha:" << _i << std::endl;
    _i++;

    struct genlmsghdr *gnlh = (struct genlmsghdr*)nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];

    struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];

    struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
    struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1];
    freq_policy[NL80211_FREQUENCY_ATTR_FREQ].type = NLA_U32;
    freq_policy[NL80211_FREQUENCY_ATTR_DISABLED].type = NLA_FLAG;
    freq_policy[NL80211_FREQUENCY_ATTR_NO_IR].type = NLA_FLAG;
    freq_policy[__NL80211_FREQUENCY_ATTR_NO_IBSS].type = NLA_FLAG;
    freq_policy[NL80211_FREQUENCY_ATTR_RADAR].type = NLA_FLAG;
    freq_policy[NL80211_FREQUENCY_ATTR_MAX_TX_POWER].type = NLA_U32;

    struct nlattr *tb_rate[NL80211_BITRATE_ATTR_MAX + 1];
    struct nla_policy rate_policy[NL80211_BITRATE_ATTR_MAX + 1];
    rate_policy[NL80211_BITRATE_ATTR_RATE].type = NLA_U32;
    rate_policy[NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE].type = NLA_FLAG;

    struct nlattr *nl_band;
    struct nlattr *nl_freq;
    struct nlattr *nl_rate;
    struct nlattr *nl_mode;
    struct nlattr *nl_cmd;
    struct nlattr *nl_if, *nl_ftype;
    int rem_band, rem_freq, rem_rate, rem_mode, rem_cmd, rem_ftype, rem_if;
    int open;

    /*
     * static variables only work here, other applications need to use the
     * callback pointer and store them there so they can be multithreaded
     * and/or have multiple netlink sockets, etc.
     */
    static int64_t phy_id = -1;
    static int last_band = -1;
    static bool band_had_freq = false;
    bool print_name = true;

    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
          genlmsg_attrlen(gnlh, 0), NULL);

    QStandardItem *itemProject = (QStandardItem*)arg;

    if (tb_msg[NL80211_ATTR_WIPHY]) {
        if (nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]) == phy_id)
            print_name = false;
        else
            last_band = -1;
        phy_id = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
    }
    if (print_name && tb_msg[NL80211_ATTR_WIPHY_NAME]) {
        itemProject->setText(QString(nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME])));
    }

    if (tb_msg[NL80211_ATTR_MAX_NUM_SCAN_SSIDS]) {
        QStandardItem *itemChild = new QStandardItem("SSID最大扫描数量");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(nla_get_u8(tb_msg[NL80211_ATTR_MAX_NUM_SCAN_SSIDS]))));
    }

    if (tb_msg[NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS]) {
        QStandardItem *itemChild = new QStandardItem("SSID最大扫描数量(scheduled)");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(nla_get_u8(tb_msg[NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS]))));
    }

    if (tb_msg[NL80211_ATTR_MAX_SCAN_IE_LEN]) {
        QStandardItem *itemChild = new QStandardItem("IEs最大扫描字节数量");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(nla_get_u16(tb_msg[NL80211_ATTR_MAX_SCAN_IE_LEN]))));
    }

    if (tb_msg[NL80211_ATTR_MAX_MATCH_SETS]) {
        QStandardItem *itemChild = new QStandardItem("max # match sets");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(nla_get_u16(tb_msg[NL80211_ATTR_MAX_MATCH_SETS]))));
    }

    if (tb_msg[NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS]) {
        QStandardItem *itemChild = new QStandardItem("max # scan plans");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(nla_get_u32(tb_msg[NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS]))));
    }

    if (tb_msg[NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL]) {
        QStandardItem *itemChild = new QStandardItem("max scan plan interval");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number((int)nla_get_u32(tb_msg[NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL]))));
    }

    if (tb_msg[NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS]) {
        QStandardItem *itemChild = new QStandardItem("max scan plan iterations");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(nla_get_u32(tb_msg[NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS]))));
    }

    if (tb_msg[NL80211_ATTR_WIPHY_FRAG_THRESHOLD]) {
        unsigned int frag = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FRAG_THRESHOLD]);
        if (frag != (unsigned int)-1) {
            QStandardItem *itemChild = new QStandardItem("Fragmentation阈值");
            itemProject->appendRow(itemChild);
            itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(frag)));
        }
    }

    if (tb_msg[NL80211_ATTR_WIPHY_RTS_THRESHOLD]) {
        unsigned int rts = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_RTS_THRESHOLD]);
        if (rts != (unsigned int)-1) {
            QStandardItem *itemChild = new QStandardItem("RTS阈值");
            itemProject->appendRow(itemChild);
            itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(rts)));
        }
    }

    if (tb_msg[NL80211_ATTR_WIPHY_RETRY_SHORT] || tb_msg[NL80211_ATTR_WIPHY_RETRY_LONG]) {
        unsigned char retry_short = 0, retry_long = 0;

        if (tb_msg[NL80211_ATTR_WIPHY_RETRY_SHORT])
            retry_short = nla_get_u8(tb_msg[NL80211_ATTR_WIPHY_RETRY_SHORT]);
        if (tb_msg[NL80211_ATTR_WIPHY_RETRY_LONG])
            retry_long = nla_get_u8(tb_msg[NL80211_ATTR_WIPHY_RETRY_LONG]);
        if (retry_short == retry_long) {
            QStandardItem *itemChild = new QStandardItem("Retry short long limit");
            itemProject->appendRow(itemChild);
            itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(retry_short)));
        } else {
            QStandardItem *itemChild = new QStandardItem("Retry short limit");
            itemProject->appendRow(itemChild);
            itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(retry_short)));

            itemChild = new QStandardItem("Retry long limit");
            itemProject->appendRow(itemChild);
            itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(retry_long)));
        }
    }

    if (tb_msg[NL80211_ATTR_WIPHY_COVERAGE_CLASS]) {
        unsigned char coverage = nla_get_u8(tb_msg[NL80211_ATTR_WIPHY_COVERAGE_CLASS]);
        /* See handle_distance() for an explanation where the '450' comes from */
        QStandardItem *itemChild = new QStandardItem("覆盖等级");
        itemProject->appendRow(itemChild);
        itemProject->setChild(itemChild->index().row(), 1, new QStandardItem(QString::number(coverage) + " (up to " + QString::number(450*coverage) + "m)"));
    }

    if (tb_msg[NL80211_ATTR_CIPHER_SUITES]) {
        int num = nla_len(tb_msg[NL80211_ATTR_CIPHER_SUITES]) / sizeof(__u32);
        __u32 *ciphers = (__u32 *)nla_data(tb_msg[NL80211_ATTR_CIPHER_SUITES]);
        if (num > 0) {
            QStandardItem *itemChild = new QStandardItem("支持密码类型");
            itemProject->appendRow(itemChild);
            for(int i = 0; i < num; i++) {
                QStandardItem *tmpitem = new QStandardItem(cipher_name(ciphers[i]));
                itemChild->appendRow(tmpitem);
            }
        }
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

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    m_devs = new QStandardItemModel(ui->treeView);
    ui->treeView->setModel(m_devs);
    m_devs->setHorizontalHeaderLabels(QStringList() << QStringLiteral("项目名") << QStringLiteral("信息"));
}

MainWindow::~MainWindow()
{
    delete ui;
    delete m_devs;
}

void MainWindow::on_mDevPushButton_clicked()
{
    engine.handle_cmd(NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, handle_dev_dump, m_devs);
    std::cout << ">>> " << std::endl;
    int nrows = m_devs->rowCount();
    QStandardItem *itemProject = m_devs->item(0);
    std::cout << nrows << ":" << itemProject->rowCount() << std::endl;
    std::cout << itemProject->text().toStdString() << ":" << m_devs->item(0, 1)->text().toStdString() << std::endl;
}



void MainWindow::on_mDevPushButton_2_clicked()
{
    QStandardItem *itemProject = new QStandardItem("Wiphy");
    m_devs->appendRow(itemProject);
    m_devs->setItem(m_devs->indexFromItem(itemProject).row(), 1, new QStandardItem("Wiphy"));

    engine.handle_cmd(NLM_F_DUMP, NL80211_CMD_GET_WIPHY, handle_info, itemProject);
    std::cout << ">>> m_devs:" << m_devs->rowCount() << std::endl;
}
