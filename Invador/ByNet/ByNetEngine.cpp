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
}
/*
 * BYNetEngine析构函数
 */
ByNetEngine::~ByNetEngine()
{
    nl_socket_free(m_nlstate.nl_sock);
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


