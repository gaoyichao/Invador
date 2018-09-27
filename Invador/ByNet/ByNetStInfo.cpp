#include "ByNetStInfo.h"

ByNetStInfo::ByNetStInfo(const unsigned char *mac)
{
    SetMac(mac);
    memset(&this->wpa, 0, sizeof(this->wpa));
    this->wpa.state = 0;

    this->channel = 0;

    this->m_ap = 0;
}

ByNetStInfo::ByNetStInfo(const ByNetMacAddr &mac)
{
    SetMac(mac);
    memset(&this->wpa, 0, sizeof(this->wpa));
    this->wpa.state = 0;

    this->channel = 0;

    this->m_ap = 0;
}

/*
 * Clone -
 */
ByNetStInfo *ByNetStInfo::Clone() const
{
    ByNetStInfo *re = new ByNetStInfo(this->m_mac);

    memcpy(&re->wpa, &this->wpa, sizeof(this->wpa));
    re->channel = this->channel;

    return re;
}
