#ifndef BYNETENGINE_H
#define BYNETENGINE_H

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

class BYNetEngine;

typedef int (*ByNetHandlerPtr)(struct nl_msg *, void *);

/*
 * ByNetHandler - 成功运行返回0,出错返回1
 */
typedef int (*ByNetHandler)(BYNetEngine *, struct nl_msg *, void *);

class BYNetEngine
{
public:
    BYNetEngine();
    ~BYNetEngine();

public:
    void prepare(enum command_identify_by cidby, signed long long devidx);
    int handle_cmd(int nlm, enum nl80211_commands cmd, ByNetHandler handler, void *arg);
private:
    struct nl80211_state m_nlstate;

    signed long long m_devidx;
    enum command_identify_by m_cidby;
};

#endif // BYNETENGINE_H
