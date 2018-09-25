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
    this->gotwpa = false;

    m_StMap.clear();
}

ByNetApInfo::~ByNetApInfo()
{

}

/*
 *  Clone - 拷贝除连接Station外的所有ApInfo
 */
ByNetApInfo *ByNetApInfo::Clone() const
{
    ByNetApInfo *re = new ByNetApInfo(this->bssid);

    memcpy(re->essid, this->essid, MAX_IE_ELEMENT_SIZE);
    memcpy(re->lanip, this->lanip, 4);
    memcpy(&re->wps, &this->wps, sizeof(this->wps));
    memcpy(&re->wpa, &this->wpa, sizeof(this->wpa));

    re->security = this->security;
    re->nb_bcn = this->nb_bcn;
    re->nb_pkt = this->nb_pkt;
    re->crypt = this->crypt;
    re->eapol = this->eapol;
    re->gotwpa = this->gotwpa;

    return re;
}

ByNetStInfo *ByNetApInfo::FindStation(unsigned char *mac)
{
    auto it = m_StMap.find(mac);
    if (m_StMap.end() != it)
        return it->second;
    return NULL;
}

ByNetStInfo *ByNetApInfo::AddStation(ByNetStInfo *st)
{
    m_StMap[st->stmac] = st;
    return st;
}

