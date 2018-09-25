#ifndef BYNETENGINE_H
#define BYNETENGINE_H

#include <QThread>
#include <QReadWriteLock>

#include <net/if.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include <nl80211.h>
#include <iw.h>

#include <stdio.h>
#include <string>
#include <map>

#include <ByNetDev.h>
#include <ByNetInterface.h>
#include <ByNetMacAddr.h>
#include <ByNetTypes.h>
#include <ByNetApInfo.h>
#include <ByNetStInfo.h>
#include <ByNetCntInfo.h>

class ByNetEngine;

typedef int (*ByNetHandlerPtr)(struct nl_msg *, void *);

/*
 * ByNetHandler - 成功运行返回0,出错返回1
 */
typedef int (*ByNetHandler)(ByNetEngine *, struct nl_msg *, void *);

/*
 * ByNetEngine
 */
class ByNetEngine : public QThread
{
public:
    ByNetEngine();
    ~ByNetEngine();
private:
    void run();

public:
    void start_monite() { m_moniting = true; this->start(); }
    void stop_monite() { m_moniting = false; }
    bool is_moniting() const { return m_moniting; }
private:
    bool m_moniting;

public:
    void prepare(enum command_identify_by cidby, signed long long devidx);
    int handle_cmd(int nlm, enum nl80211_commands cmd, ByNetHandler handler, void *arg);
    void init_dump_file(char const *fname);
    void close_dump_file();
    FILE *get_dump_file() { return m_fcap; }

public:
    int DumpPacket(unsigned char *buf, int caplen, struct rx_info *ri, FILE *f_cap);
    ByNetApInfo *ParsePacket(unsigned char *buf, int caplen);
    ByNetCntInfo *GetCntInfo();
private:
    void ParseProbeRequest(unsigned char *buf, int caplen, ByNetStInfo *st);
    void ParseBeaconProbeResponse(unsigned char *buf, int caplen, ByNetApInfo *ap);
    void ParseAssociationRequest(unsigned char *buf, int caplen, ByNetApInfo *ap);
    void ParseData(unsigned char *buf, int caplen, ByNetApInfo *ap, ByNetStInfo *st);
private:
    ByNetCntInfo m_CntInfo;
    QReadWriteLock m_CntLock;

private:
    struct nl80211_state m_nlstate;
    signed long long m_devidx;
    enum command_identify_by m_cidby;
    FILE *m_fcap;

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

