#ifndef BYNETDEV_H
#define BYNETDEV_H

#include <nl80211.h>
#include <iw.h>

#include <string>
#include <vector>
#include <map>

#include <ByNetInterface.h>

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


class ByNetDev
{
public:
    ByNetDev();

public:
    std::map<__u32, ByNetInterface> const & GetAllInterfaces() const { return m_interfaces; }
    ByNetInterface * GetInterface(__u32 ifidx) {
        auto it = m_interfaces.find(ifidx);
        if (it != m_interfaces.end())
            return &(it->second);
        return NULL;
    }

    ByNetInterface const * GetInterface(__u32 ifidx) const {
        auto it = m_interfaces.find(ifidx);
        if (it != m_interfaces.end())
            return &(it->second);
        return NULL;
    }

    ByNetInterface * AddInterface(__u32 ifidx) {
        m_interfaces[ifidx] = ByNetInterface();
        return &(m_interfaces[ifidx]);
    }

    ByNetInterface * FindMonitorInterface() {
        ByNetInterface *monitor = NULL;
        for (auto it = m_interfaces.begin(); it != m_interfaces.end(); it++) {
            if (NL80211_IFTYPE_MONITOR == it->second.GetIfType()) {
                monitor = &(it->second);
                break;
            }
        }
        return monitor;
    }

private:
    std::map<__u32, ByNetInterface> m_interfaces;

public:
    __u32 GetPhyIndex() const { return m_PhyIndex; }
    void SetPhyIndex(__u32 i) { m_PhyIndex = i; }

    std::string const & GetPhyName() const { return m_PhyName; }
    void SetPhyName(std::string const & name) { m_PhyName = name; }

    int GetMaxNumScanSSID() const { return m_maxNumScanSsid; }
    void SetMaxNumScanSSID(int num) { m_maxNumScanSsid = num; }

    int GetMaxNumSchedScanSsid() const { return m_maxNumSchedScanSsid; }
    void SetMaxNumSchedScanSsid(int num) { m_maxNumSchedScanSsid = num; }

    int GetMaxScanIELen() const { return m_maxScanIELen; }
    void SetMaxScanIELen(int len) { m_maxScanIELen = len; }

    int GetMaxMatchSets() const { return m_maxMatchSets; }
    void SetMaxMatchSets(int num) { m_maxMatchSets = num; }

    int GetMaxNumSchedScanPlans() const { return m_maxNumSchedScanPlans; }
    void SetMaxNumSchedScanPlans(int num) { m_maxNumSchedScanPlans = num; }

    int GetMaxScanPlanInterval() const { return m_maxScanPlanInterval; }
    void SetMaxScanPlanInterval(int num) { m_maxScanPlanInterval = num; }

    int GetMaxScanPlanIterations() const { return m_maxScanPlanIterations; }
    void SetMaxScanPlanIterations(int num) { m_maxScanPlanIterations = num; }

    int GetPhyFragThreshold() const { return m_phyFragThreshold; }
    void SetPhyFragThreshold(int frag) { m_phyFragThreshold = frag; }

    int GetPhyRtsThreshold() const { return m_phyRtsThreshold; }
    void SetPhyRtsThreshold(int rts) { m_phyRtsThreshold = rts; }

    int GetRetryShort() const { return m_retryShort; }
    void SetRetryShort(int mshort) { m_retryShort = mshort; }

    int GetRetryLong() const { return m_retryLong; }
    void SetRetryLong(int mlong) { m_retryLong = mlong; }

    int GetCoverageClass() const { return m_coverageClass; }
    int GetCoverageDistance() const { return 450 * m_coverageClass; }
    void SetCoverageClass(int cov) { m_coverageClass = cov; }

    std::vector<__u32> const & GetSupportedCiphers() const { return m_SupportedCiphers; }
    void SetSupportedCiphers(__u32 const *ciphers, int num) {
        m_SupportedCiphers.clear();
        for (int i = 0; i < num; i++)
            m_SupportedCiphers.push_back(ciphers[i]);
    }

    __u32 GetAvailAntennaTx() const { return m_availAntennaTx; }
    void SetAvailAntennaTx(__u32 tx) { m_availAntennaTx = tx; }

    __u32 GetAvailAntennaRx() const { return m_availAntennaRx; }
    void SetAvailAntennaRx(__u32 rx) { m_availAntennaRx = rx; }

    __u32 GetCfgAntennaTx() const { return m_cfgAntennaTx; }
    void SetCfgAntennaTx(__u32 tx) { m_cfgAntennaTx = tx; }

    __u32 GetCfgAntennaRx() const { return m_cfgAntennaRx; }
    void SetCfgAntennaRx(__u32 rx) { m_cfgAntennaRx = rx; }

    std::vector<enum nl80211_iftype> const & GetSupportedIfTypes() const { return m_SupportedIfTypes; }
    void AddSupportedIfType(enum nl80211_iftype iftype) { m_SupportedIfTypes.push_back(iftype); }
    void ClearSupportedIfType() { m_SupportedIfTypes.clear(); }

    std::vector<enum nl80211_iftype> const & GetSoftwareIfTypes() const { return m_SoftwareIfTypes; }
    void AddSoftwareIfType(enum nl80211_iftype iftype) { m_SoftwareIfTypes.push_back(iftype); }
    void ClearSoftwareIfType() { m_SoftwareIfTypes.clear(); }

    std::vector<enum nl80211_commands> const & GetSupportedCmd() const { return m_SupportedCmd; }
    void AddSupportedCmd(enum nl80211_commands cmd) { m_SupportedCmd.push_back(cmd); }
    void ClearSupportedCmd() { m_SupportedCmd.clear(); }

private:
    __u32 m_PhyIndex;
    __u32 m_availAntennaTx;
    __u32 m_availAntennaRx;
    __u32 m_cfgAntennaTx;
    __u32 m_cfgAntennaRx;

    int m_maxNumScanSsid;
    int m_maxNumSchedScanSsid;
    int m_maxScanIELen;
    int m_maxMatchSets;
    int m_maxNumSchedScanPlans;
    int m_maxScanPlanInterval;
    int m_maxScanPlanIterations;
    int m_phyFragThreshold;
    int m_phyRtsThreshold;
    int m_retryShort;
    int m_retryLong;
    int m_coverageClass;

    std::string m_PhyName;

    std::vector<__u32> m_SupportedCiphers;
    std::vector<enum nl80211_iftype> m_SupportedIfTypes;
    std::vector<enum nl80211_iftype> m_SoftwareIfTypes;
    std::vector<enum nl80211_commands> m_SupportedCmd;
};

#endif // BYDEV_H
