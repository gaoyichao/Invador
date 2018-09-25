#include "ByNetStInfo.h"

ByNetStInfo::ByNetStInfo(const unsigned char *mac)
{
    memcpy(this->stmac, mac, 6);
    memset(&this->wpa, 0, sizeof(this->wpa));
    this->wpa.state = 0;

    this->channel = 0;

    this->m_base = 0;
}
/*
 * Clone -
 */
ByNetStInfo *ByNetStInfo::Clone() const
{
    ByNetStInfo *re = new ByNetStInfo(this->stmac);

    memcpy(&re->wpa, &this->wpa, sizeof(this->wpa));
    re->channel = this->channel;

    return re;
}

