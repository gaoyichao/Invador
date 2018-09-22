#include "ByNetApInfo.h"

ByNetApInfo::ByNetApInfo(const unsigned char *bssid)
{
    memcpy(this->bssid, bssid, 6);
    memset(this->essid, 0, MAX_IE_ELEMENT_SIZE);
    memset(this->lanip, 0, 4);
    memset(&this->wps, 0, sizeof(this->wps));
    memset(&this->wpa, 0, sizeof(this->wpa));

    this->security = 0;
    this->nb_bcn = 0;
    this->nb_pkt = 0;
    this->crypt = 0;
    this->eapol = 0;
    this->ivbuf = 0;
    this->gotwpa = false;

    m_StMap.clear();
}

ByNetApInfo::~ByNetApInfo()
{
    if (0 != ivbuf)
        free(ivbuf);
}

ByNetStInfo *ByNetApInfo::FindStation(unsigned char *mac)
{
    auto it = m_StMap.find(mac);
    if (m_StMap.end() != it)
        return it->second;
    return NULL;
}

ByNetStInfo *ByNetApInfo::AddStation(unsigned char *mac)
{
    ByNetStInfo *st_cur = new ByNetStInfo(mac);
    if (!st_cur)
        return 0;

    m_StMap[mac] = st_cur;
    memset(st_cur, 0, sizeof(ByNetStInfo));

    memcpy(st_cur->stmac, mac, 6);
    return st_cur;
}

