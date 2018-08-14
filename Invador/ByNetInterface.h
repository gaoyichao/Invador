#ifndef BYNETINTERFACE_H
#define BYNETINTERFACE_H

#include <nl80211.h>
#include <iw.h>

#include <string>
#include <vector>


class ByNetInterface
{
public:
    ByNetInterface();

public:
    std::string const & GetIfName() const { return m_IfName; }
    void SetIfName(std::string const & name) { m_IfName = name; }

    __u32 GetIfIndex() const { return m_IfIndex; }
    void SetIfIndex(__u32 i) { m_IfIndex = i; }

    __u64 GetWDev() const { return m_wdev; }
    void SetWDev(__u64 wdev) { m_wdev = wdev; }

    uint8_t const * GetMac() const { return m_mac; }
    void SetMac(uint8_t const * mac) {
        for (int i = 0; i < 6; i++)
            m_mac[i] = mac[i];
    }

    uint8_t const * GetSSID() const { return m_ssid; }
    int GetSSIDLen() const { return m_ssid_len; }
    void SetSSID(uint8_t const *ssid, int len) {
        len = (len < 32) ? len : 32;
        m_ssid_len = len;
        for (int i = 0; i < len; i++)
            m_ssid[i] = ssid[i];
    }

    enum nl80211_iftype GetIfType() const { return m_IfType; }
    void SetIfType(enum nl80211_iftype type) { m_IfType = type; }

    __u32 GetFreq() const { return m_freq; }
    int GetChannel() const { return m_channel; }
    void SetFreq(__u32 freq) {
        m_freq = freq;
        m_channel = ieee80211_frequency_to_channel(freq);
    }

    enum nl80211_chan_width GetChannelWidth() const { return m_ChanWidth; }
    void SetChannelWidth(enum nl80211_chan_width width) { m_ChanWidth = width; }

    __u32 GetCenterFreq1() const { return m_cfreq1; }
    void SetCenterFreq1(__u32 freq) { m_cfreq1 = freq; }

    __u32 GetCenterFreq2() const { return m_cfreq2; }
    void SetCenterFreq2(__u32 freq) { m_cfreq2 = freq; }

    __u32 GetTxPowerLevel() const { return m_txpow; }
    void SetTxPowerLevel(__u32 txpow) { m_txpow = txpow; }

private:
    __u32 m_IfIndex;
    __u32 m_freq;
    __u32 m_cfreq1;
    __u32 m_cfreq2;
    __u32 m_txpow;

    int m_channel;

    __u64 m_wdev;

    uint8_t m_mac[6];
    uint8_t m_ssid[32];

    int m_ssid_len;

    enum nl80211_iftype m_IfType;
    enum nl80211_chan_width m_ChanWidth;

    std::string m_IfName;

};

#endif // BYNETINTERFACE_H
