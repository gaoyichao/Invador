#include "ByNetStInfo.h"

ByNetStInfo::ByNetStInfo(const unsigned char *mac)
{
    memcpy(this->stmac, mac, 6);
    memset(&this->wpa, 0, sizeof(this->wpa));
    this->wpa.state = 0;

    this->base = 0;
    this->channel = 0;
}
