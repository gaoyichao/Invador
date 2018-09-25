#include "ByNetEngine.h"
#include <iostream>

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
    int *ret = (int*)arg;
    *ret = err->error;
    return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
    int *ret = (int*)arg;
    *ret = 0;
    return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
    int *ret = (int*)arg;
    *ret = 0;
    return NL_STOP;
}

static int (*registered_handler)(struct nl_msg *, void *);
static void *registered_handler_data;

void register_handler(ByNetHandlerPtr handler, void *data)
{
    registered_handler = handler;
    registered_handler_data = data;
}

int valid_handler(struct nl_msg *msg, void *arg)
{
    if (registered_handler)
        return registered_handler(msg, registered_handler_data);

    return NL_OK;
}

/**********************************************************************/


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

int print_phy_handler(struct nl_msg *msg, void *arg)
{
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

int handle_dev_dump(ByNetEngine *engine, struct nl_msg *msg, void *arg)
{
    register_handler(print_iface_handler, &(engine->GetDevs()));
    return 0;
}

int handle_feature(ByNetEngine *engine, struct nl_msg *msg, void *arg)
{
    register_handler(print_feature_handler, NULL);
    return 0;
}

int handle_info(ByNetEngine *engine, struct nl_msg *msg, void *arg)
{
    engine->handle_cmd(0, NL80211_CMD_GET_PROTOCOL_FEATURES, handle_feature, NULL);
    if (nl80211_has_split_wiphy) {
        nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
        nlmsg_hdr(msg)->nlmsg_flags |= NLM_F_DUMP;
    }

    register_handler(print_phy_handler, &(engine->GetDevs()));

    return 0;
}

int handle_interface_add(ByNetEngine *engine, struct nl_msg *msg, void *arg)
{
    NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, "moni0");
    NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);
    return 0;
nla_put_failure:
    return -ENOBUFS;
}

int handle_interface_del(ByNetEngine *engine, struct nl_msg *msg, void *arg)
{
    return 0;
}


/**********************************************************************/

/*
 * BYNetEngine默认构造函数
 */
ByNetEngine::ByNetEngine()
{
    m_nlstate.nl_sock = nl_socket_alloc();
    if (!m_nlstate.nl_sock)
        throw "Failed to allocate netlink socket";

    if (genl_connect(m_nlstate.nl_sock)) {
        nl_socket_free(m_nlstate.nl_sock);
        throw "Failed to connect to generic netlink";
    }

    nl_socket_set_buffer_size(m_nlstate.nl_sock, 8192, 8192);

    m_nlstate.nl80211_id = genl_ctrl_resolve(m_nlstate.nl_sock, "nl80211");
    if (m_nlstate.nl80211_id < 0) {
        nl_socket_free(m_nlstate.nl_sock);
        throw "nl80211 not found";
    }

    m_cidby = CIB_NONE;
    m_moniting = false;
    m_fcap = NULL;

    m_CntInfo.Clear();
}
/*
 * BYNetEngine析构函数
 */
ByNetEngine::~ByNetEngine()
{
    nl_socket_free(m_nlstate.nl_sock);
    close_dump_file();
}

#include <iostream>
int ByNetEngine::handle_cmd(int nlm, enum nl80211_commands cmd, ByNetHandler handler, void *arg)
{
    int err;
    struct nl_msg *msg = nlmsg_alloc();
    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);

    genlmsg_put(msg, 0, 0, m_nlstate.nl80211_id, 0, nlm, cmd, 0);

    switch (m_cidby) {
    case CIB_PHY:
        NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, m_devidx);
        break;
    case CIB_NETDEV:
        NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, m_devidx);
        break;
    case CIB_WDEV:
        NLA_PUT_U64(msg, NL80211_ATTR_WDEV, m_devidx);
        break;
    default:
        break;
    }

    err = handler(this, msg, arg);
    if (err)
        goto out;

    err = nl_send_auto_complete(m_nlstate.nl_sock, msg);
    if (err < 0)
        goto out;

    err = 1;
    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);

    while (err > 0)
        nl_recvmsgs(m_nlstate.nl_sock, cb);

    m_cidby = CIB_NONE;
out:
    nl_cb_put(cb);
    nlmsg_free(msg);
    return err;

nla_put_failure:
    std::cerr << "building message failed" << std::endl;
    return 2;
}

void ByNetEngine::prepare(enum command_identify_by cidby, signed long long devidx)
{
    m_cidby = cidby;
    m_devidx = devidx;
}

std::map<__u32, ByNetDev> & ByNetEngine::UpdateDevs()
{
    ClearDevs();
    handle_cmd(NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, handle_dev_dump, NULL);
    handle_cmd(NLM_F_DUMP, NL80211_CMD_GET_WIPHY, handle_info, NULL);
    return GetDevs();
}

ByNetInterface * ByNetEngine::FindMonitorInterface()
{
    ByNetInterface *interface = NULL;

    UpdateDevs();
    for (auto it = m_devs.begin(); it != m_devs.end(); it++) {
        ByNetDev *dev = &(it->second);
        interface = dev->FindMonitorInterface();
        if (NULL != interface)
            return interface;
    }

    return NULL;
}

void ByNetEngine::init_dump_file(const char *fname)
{
    if (is_moniting())
        throw "请停止监听再配置文件!!!";

    m_fcap = fopen(fname, "wb+");
    if (NULL == m_fcap)
        throw "无法打开*.cap文件";

    struct pcap_file_header pfh;
    pfh.magic = TCPDUMP_MAGIC;
    pfh.version_major = PCAP_VERSION_MAJOR;
    pfh.version_minor = PCAP_VERSION_MINOR;
    pfh.thiszone = 0;
    pfh.sigfigs = 0;
    pfh.snaplen = 65535;
    pfh.linktype = LINKTYPE_IEEE802_11;

    if (sizeof(pfh) != fwrite(&pfh, 1, sizeof(pfh), m_fcap))
        throw "写*.cap文件头错误";
}

void ByNetEngine::close_dump_file()
{
    if (NULL != m_fcap)
        fclose(m_fcap);
    m_fcap = NULL;
}

#include <aircrack-util/common_util.h>
#include <aircrack-util/verifyssid.h>
#include <aircrack-util/mcs_index_rates.h>

#include <stdio.h>
const unsigned char llcnull[4] = {0, 0, 0, 0};
#define BROADCAST (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF"

ByNetCntInfo *ByNetEngine::GetCntInfo()
{
    QReadLocker locker(&m_CntLock);
    return m_CntInfo.Clone();
}

void ByNetEngine::ParseProbeRequest(unsigned char *buf, int caplen, ByNetStInfo *st)
{
    unsigned char *p = buf + 24;
    unsigned char *bufend = buf + caplen;

    while (p < bufend) {
        if (p + 2 + p[1] > bufend)
            break;
        if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0' && (p[1] > 1 || p[2] != ' ')) {
            int n = p[1];

            for (int i = 0; i < n; i++) {
                if (p[2+i] > 0 && p[2+i] < ' ')
                    return;
                // todo: probed essid
            }
        }
        p += 2 + p[1];
    }
}

void ByNetEngine::ParseBeaconProbeResponse(unsigned char *buf, int caplen, ByNetApInfo *ap)
{
    unsigned char *p = buf + 36;
    unsigned char *bufend = buf + caplen;
    while (p < bufend) {
        if (p + 2 + p[1] > bufend)
            break;

        if (0x00 == p[0] && p[1] > 0 && p[2] != '\0') {
            /* found a non-cloaked ESSID */
            int n = (p[1] > 32) ? 32 : p[1];
            memset(ap->essid, 0, 33);
            memcpy(ap->essid, p+2, n);
            //std::cout << "Beacon p[1] = " << n << ":" << ap->essid << std::endl;
        }
        p += 2 + p[1];
    }
}

void ByNetEngine::ParseAssociationRequest(unsigned char *buf, int caplen, ByNetApInfo *ap)
{
    unsigned char *p = buf + 28;
    unsigned char *bufend = buf + caplen;

    while (p < bufend) {
        if (p + 2 + p[1] > bufend)
            break;

        if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0') {
            int n = (p[1] > 32) ? 32 : p[1];

            memset(ap->essid, 0, 33);
            memcpy(ap->essid, p + 2, n);
            //std::cout << "Association Request p[1] = " << p[1];
            //std::cout << ":" << ap->essid << std::endl;
        }
        p += 2 + p[1];
    }
}

void ByNetEngine::ParseData(unsigned char *buf, int caplen, ByNetApInfo *ap, ByNetStInfo *st)
{
    unsigned z = ((buf[1] & 3) != 3) ? 24 : 30;

    if ((buf[0] & 0x80) == 0x80)
        z += 2; /* 802.11e QoS */
    if (z + 16 > caplen)
        return;

    /* no encryption */
    if (ap->crypt < 0)
        ap->crypt = 0;

    z += 6;
    if (z + 20 < caplen) {
        if (buf[z] == 0x08 && buf[z + 1] == 0x00 && (buf[1] & 3) == 0x01)
            memcpy(ap->lanip, &buf[z + 14], 4);

        if (buf[z] == 0x08 && buf[z + 1] == 0x06)
            memcpy(ap->lanip, &buf[z + 16], 4);
    }
    /* check ethertype == EAPOL */
    if (buf[z] != 0x88 || buf[z + 1] != 0x8E)
        return;
    z += 2;
    ap->eapol = 1;

    /* type == 3 (key), desc. == 254 (WPA) or 2 (RSN) */
    if (buf[z + 1] != 0x03 || (buf[z + 4] != 0xFE && buf[z + 4] != 0x02))
        return;
    ap->eapol = 0;
    ap->crypt = 3; /* set WPA */
    if (NULL == st) {
        return;
    }

    /* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */
    if ((buf[z + 6] & 0x08) != 0 && (buf[z + 6] & 0x40) == 0
        && (buf[z + 6] & 0x80) != 0 && (buf[z + 5] & 0x01) == 0) {
        memcpy(st->wpa.anonce, &buf[z + 17], 32);
        /* authenticator nonce set */
        st->wpa.state = 1;
    }

    /* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */
    if ((buf[z + 6] & 0x08) != 0 && (buf[z + 6] & 0x40) == 0
        && (buf[z + 6] & 0x80) == 0 && (buf[z + 5] & 0x01) != 0) {
        if (memcmp(&buf[z + 17], ZERO, 32) != 0) {
            memcpy(st->wpa.snonce, &buf[z + 17], 32);
            /* supplicant nonce set */
            st->wpa.state |= 2;
        }

        if (4 != (st->wpa.state & 4)) {
            /* copy the MIC & eapol frame */
            st->wpa.eapol_size = (buf[z + 2] << 8) + buf[z + 3] + 4;
            if (st->wpa.eapol_size == 0 || st->wpa.eapol_size > sizeof(st->wpa.eapol) || caplen - z < st->wpa.eapol_size) {
                // Ignore the packet trying to crash us.
                st->wpa.eapol_size = 0;
                return;
            }
            memcpy(st->wpa.keymic, &buf[z + 81], 16);
            memcpy(st->wpa.eapol, &buf[z], st->wpa.eapol_size);
            memset(st->wpa.eapol + 81, 0, 16);
            printf(">>> get keymic <<<\n");

            /* eapol frame & keymic set */
            st->wpa.state |= 4;
            /* copy the key descriptor version */
            st->wpa.keyver = buf[z + 6] & 7;
        }
    }
    /* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */
    if ((buf[z + 6] & 0x08) != 0 && (buf[z + 6] & 0x40) != 0
        && (buf[z + 6] & 0x80) != 0 && (buf[z + 5] & 0x01) != 0) {
        if (memcmp(&buf[z + 17], ZERO, 32) != 0) {
            memcpy(st->wpa.anonce, &buf[z + 17], 32);
            /* authenticator nonce set */
            st->wpa.state |= 1;
        }

        if ((st->wpa.state & 4) != 4) {
            /* copy the MIC & eapol frame */
            st->wpa.eapol_size = (buf[z + 2] << 8) + buf[z + 3] + 4;

            if (st->wpa.eapol_size == 0 || st->wpa.eapol_size > sizeof(st->wpa.eapol) || caplen - z < st->wpa.eapol_size) {
                // Ignore the packet trying to crash us.
                st->wpa.eapol_size = 0;
                return;
            }

            memcpy(st->wpa.keymic, &buf[z + 81], 16);
            memcpy(st->wpa.eapol, &buf[z], st->wpa.eapol_size);
            memset(st->wpa.eapol + 81, 0, 16);
            printf(">>> get keymic <<<\n");

            /* eapol frame & keymic set */
            st->wpa.state |= 4;

            /* copy the key descriptor version */
            st->wpa.keyver = buf[z + 6] & 7;
        }
    }

    if (st->wpa.state == 7) {
        /* got one valid handshake */
        memcpy(&ap->wpa, &st->wpa, sizeof(struct WPA_hdsk));
        ap->gotwpa = true;
        printf("WPA handshake: %02X:%02X:%02X:%02X:%02X:%02X\n",
            ap->bssid[0],
            ap->bssid[1],
            ap->bssid[2],
            ap->bssid[3],
            ap->bssid[4],
            ap->bssid[5]);
    }
}

ByNetApInfo *ByNetEngine::ParsePacket(unsigned char *buf, int caplen)
{
    QWriteLocker locker(&m_CntLock);

    unsigned char bssid[6];
    unsigned char stmac[6];

    ByNetApInfo *ap_cur = 0;
    ByNetStInfo *st_cur = 0;
    // todo: 主动扫描模式暂未实现

    /* skip packets smaller than a 802.11 header */
    if (caplen < 24)
        return 0;

    /* skip (uninteresting) control frames */
    if (0x04 == (buf[0] & 0x0C))
        return 0;

    /* if it's a LLC null packet, just forget it (may change in the future) */
    if (caplen > 128) {
        if (memcmp(buf + 24, llcnull, 4) == 0)
            return 0;
    }

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
    ap_cur = m_CntInfo.FindAp(bssid);
    if (NULL == ap_cur)
        ap_cur = m_CntInfo.AddAp(bssid);
    // todo: 更新ap信号强度

    switch (buf[0]) {
    case 0x80:
        ap_cur->nb_bcn++;
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
    st_cur = m_CntInfo.FindStation(stmac);
    if (NULL == st_cur) {
        st_cur = m_CntInfo.AddStation(stmac);
        memcpy(st_cur->wpa.stmac, stmac, 6);
    }

    if (!st_cur->IsConnected() || memcmp(ap_cur->bssid, BROADCAST, 6) != 0)
        st_cur->SetAp(ap_cur);
    // todo: 更新station信号强度

skip_station:
    /*
    if (buf[0] == 0x40 && st_cur != NULL)
        ParseProbeRequest(buf, caplen, st_cur);
     */

    if (buf[0] == 0x80 || buf[0] == 0x50)
        ParseBeaconProbeResponse(buf, caplen, ap_cur);

    if (buf[0] == 0x00 && caplen > 28)
        ParseAssociationRequest(buf, caplen, ap_cur);

    /* packet parsing: Association Response */
    if (buf[0] == 0x10) {
        /* reset the WPA handshake state */
        if (st_cur != NULL)
            st_cur->wpa.state = 0;
        //std::cout << "Reset Response!!!" << std::endl;
    }

    // packet parsing: some data
    if ((buf[0] & 0x0C) == 0x08)
        ParseData(buf, caplen, ap_cur, st_cur);

    if (ap_cur->gotwpa)
        std::cout << ">>> ap_cur gotwpa" << std::endl;
    return ap_cur;
}

int ByNetEngine::DumpPacket(unsigned char *buf, int caplen, rx_info *ri, FILE *f_cap)
{
    struct pcap_pkthdr pkh;
    struct timeval tv;

    if (f_cap != NULL && caplen >= 10) {

        gettimeofday(&tv, NULL);

        pkh.caplen = pkh.len = caplen;
        pkh.tv_sec = tv.tv_sec;
        pkh.tv_usec = (tv.tv_usec & ~0x1ff) + ri->ri_power + 64;

        int n = sizeof(pkh);
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

void ByNetEngine::run()
{
    ByNetInterface *moninterface = FindMonitorInterface();
    if (NULL == moninterface)
        return;

    moninterface->Open();

    int fd_raw = moninterface->GetFd();
    int fdh = 0;
    if (fd_raw > fdh)
        fdh = fd_raw;

    fd_set rfds;
    struct timeval tv0;
    unsigned char buffer[4096];
    struct rx_info ri;
    int read_failed_count = 0;

    while (is_moniting()) {
        FD_ZERO(&rfds);
        FD_SET(fd_raw, &rfds);
        tv0.tv_sec = 0;
        tv0.tv_usec = REFRESH_RATE;
        select(fdh+1, &rfds, NULL, NULL, &tv0);

        if (FD_ISSET(fd_raw, &rfds)) {
            memset(buffer, 0, sizeof(buffer));
            int caplen = moninterface->Read(buffer, sizeof(buffer), &ri);
            if (-1 == caplen) {
                read_failed_count++;
                std::cerr << ">>> Read Failed!!! " << read_failed_count << std::endl;
            } else {
                read_failed_count = 0;
                ParsePacket(buffer, caplen);
                DumpPacket(buffer, caplen, &ri, m_fcap);
            }
        }
    }

    if (NULL != m_fcap)
        fflush(m_fcap);
}


