#ifndef BYNETCNTINFO_H
#define BYNETCNTINFO_H

#include <ByNetMacAddr.h>
#include <ByNetApInfo.h>
#include <ByNetStInfo.h>

#include <map>

class ByNetCntInfo
{
public:
    ByNetCntInfo();
    ~ByNetCntInfo();
public:
    void Clear();
    ByNetCntInfo *Clone() const;
    ByNetApInfo *FindAp(unsigned char *bssid);
    ByNetApInfo *AddAp(unsigned char *bssid);
    ByNetApInfo *AddAp(ByNetApInfo *ap);

    ByNetStInfo *FindStation(unsigned char *mac);
    ByNetStInfo *AddStation(ByNetStInfo *st);
    ByNetStInfo *AddStation(unsigned char *mac);

public:
    std::map<ByNetMacAddr, ByNetApInfo *> &GetApMap() { return m_ApMap; }
    std::map<ByNetMacAddr, ByNetApInfo *> const &GetApMap() const { return m_ApMap; }
    std::map<ByNetMacAddr, ByNetStInfo *> &GetStMap() { return m_StMap; }
    std::map<ByNetMacAddr, ByNetStInfo *> const &GetStMap() const { return m_StMap; }
private:
    std::map<ByNetMacAddr, ByNetApInfo *> m_ApMap;
    std::map<ByNetMacAddr, ByNetStInfo *> m_StMap;
};

#endif // BYNETCNTINFO_H
