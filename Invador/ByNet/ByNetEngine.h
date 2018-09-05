#ifndef BYNETENGINE_H
#define BYNETENGINE_H

#include <net/if.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include <nl80211.h>
#include <iw.h>

#include <string>
#include <map>

#include <ByNetDev.h>
#include <ByNetInterface.h>

class ByNetEngine;

typedef int (*ByNetHandlerPtr)(struct nl_msg *, void *);

/*
 * ByNetHandler - 成功运行返回0,出错返回1
 */
typedef int (*ByNetHandler)(ByNetEngine *, struct nl_msg *, void *);

/*
 * ByNetEngine
 */
class ByNetEngine
{
public:
    ByNetEngine();
    ~ByNetEngine();

public:
    void prepare(enum command_identify_by cidby, signed long long devidx);
    int handle_cmd(int nlm, enum nl80211_commands cmd, ByNetHandler handler, void *arg);
private:
    struct nl80211_state m_nlstate;

    signed long long m_devidx;
    enum command_identify_by m_cidby;

public:
    std::map<__u32, ByNetDev> & GetDevs() { return m_devs; }
    std::map<__u32, ByNetDev> const & GetDevs() const { return m_devs; }
    void ClearDevs() { m_devs.clear(); }

    ByNetInterface * FindMonitorInterface();
    std::map<__u32, ByNetDev> & UpdateDevs();
private:
    std::map<__u32, ByNetDev> m_devs;
};

int print_iface_handler(struct nl_msg *msg, void *arg);
int print_feature_handler(struct nl_msg *msg, void *arg);
int print_phy_handler(struct nl_msg *msg, void *arg);

int handle_dev_dump(ByNetEngine *engine, struct nl_msg *msg, void *arg);
int handle_feature(ByNetEngine *engine, struct nl_msg *msg, void *arg);
int handle_info(ByNetEngine *engine, struct nl_msg *msg, void *arg);
int handle_interface_add(ByNetEngine *engine, struct nl_msg *msg, void *arg);
int handle_interface_del(ByNetEngine *engine, struct nl_msg *msg, void *arg);

#endif // BYNETENGINE_H

