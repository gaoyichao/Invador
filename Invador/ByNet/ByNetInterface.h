#ifndef BYNETINTERFACE_H
#define BYNETINTERFACE_H

#include <nl80211.h>
#include <iw.h>

#include <pcap.h>
#include <eapol.h>

#include <string>
#include <vector>
#include <map>

#include <ByNetTypes.h>

class ByNetInterface
{
public:
    ByNetInterface();
    ~ByNetInterface();

public:
    int Open();
    int GetFd() const { return fd_in; }
    int Read(unsigned char *buf, int count, struct rx_info *ri);
private:
    void OpenRaw(int fd, int *arptype);

private:
    int fd_in;
    int fd_main;
    int fd_out;
    int arptype_out;
    int arptype_in;

    unsigned char wpa_bssid[6]; // the wpa handshake bssid
    char message[512];
    char decloak;

public:
    std::string const & GetIfName() const { return m_ifname; }
    void SetIfName(std::string const & name) { m_ifname = name; }

    __u32 GetIfIndex() const { return m_ifindex; }
    void SetIfIndex(__u32 i) { m_ifindex = i; }

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
    __u32 m_ifindex;
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

    std::string m_ifname;

public:
    bool is_mac80211();
    bool is_ipw2200();
    bool is_bcm43xx();

private:
    const char *m_iwpriv;
    const char *m_iwconfig;
    const char *m_ifconfig;

    enum driver_type m_drivertype;
};

#endif // BYNETINTERFACE_H
