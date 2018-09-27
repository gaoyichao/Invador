#include "ByNetCntInfo.h"

ByNetCntInfo::ByNetCntInfo()
{

}

ByNetCntInfo::~ByNetCntInfo()
{
    Clear();
}

void ByNetCntInfo::Clear()
{
    for (auto it = m_ApMap.begin(); it != m_ApMap.end(); it++) {
        if (0 != it->second)
            delete it->second;
    }
    m_ApMap.clear();

    for (auto it = m_StMap.begin(); it != m_StMap.end(); it++) {
        if (0 != it->second)
            delete it->second;
    }
    m_StMap.clear();
}

ByNetApInfo *ByNetCntInfo::FindAp(unsigned char const *bssid)
{
    auto it = m_ApMap.find(bssid);
    if (m_ApMap.end() != it)
        return it->second;

    return NULL;
}

ByNetApInfo *ByNetCntInfo::AddAp(unsigned char *bssid)
{
    ByNetApInfo *ap_cur = new ByNetApInfo(bssid);
    return AddAp(ap_cur);
}

ByNetApInfo *ByNetCntInfo::AddAp(ByNetApInfo *ap)
{
    m_ApMap[ap->GetBssidRaw()] = ap;
    return ap;
}

ByNetStInfo *ByNetCntInfo::FindStation(unsigned char *mac)
{
    auto it = m_StMap.find(mac);
    if (m_StMap.end() != it)
        return it->second;
    return NULL;
}

ByNetStInfo *ByNetCntInfo::AddStation(unsigned char *mac)
{
    ByNetStInfo *st_cur = new ByNetStInfo(mac);
    st_cur->channel = 0;

    return AddStation(st_cur);
}

ByNetStInfo *ByNetCntInfo::AddStation(ByNetStInfo *st)
{
    m_StMap[st->GetMacRaw()] = st;
    return st;
}

ByNetCntInfo *ByNetCntInfo::Clone() const
{
    ByNetCntInfo *re = new ByNetCntInfo();

    for (auto it = m_ApMap.begin(); it != m_ApMap.end(); it++) {
        re->AddAp(it->second->Clone());
    }

    for (auto it = m_StMap.begin(); it != m_StMap.end(); it++) {
        ByNetStInfo *src = it->second;
        ByNetStInfo *dst = re->AddStation(src->Clone());

        if (src->IsConnected()) {
            ByNetApInfo *ap = re->FindAp(src->GetAp()->GetBssidRaw());
            dst->SetAp(ap);
            ap->AddStation(dst);
        } else {
            dst->SetAp(0);
        }
    }

    return re;
}


