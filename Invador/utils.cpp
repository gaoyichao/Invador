#include <nl80211.h>
#include <iw.h>

#include <ByNetEngine.h>

#include <thread>

#include <stdio.h>
#include <dirent.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <crctable_osdep.h>

void print_ssid_escaped(const uint8_t len, const uint8_t *data)
{
    int i;

    for (i = 0; i < len; i++) {
        if (isprint(data[i]) && data[i] != ' ' && data[i] != '\\')
            printf("%c", data[i]);
        else if (data[i] == ' ' &&  (i != 0 && i != len -1))
            printf(" ");
        else
            printf("\\x%.2x", data[i]);
    }
}

static const char *ifmodes[NL80211_IFTYPE_MAX + 1] = {
    "unspecified",
    "IBSS",
    "managed",
    "AP",
    "AP/VLAN",
    "WDS",
    "monitor",
    "mesh point",
    "P2P-client",
    "P2P-GO",
    "P2P-device",
    "outside context of a BSS",
    "NAN",
};

static char modebuf[100];

const char *iftype_name(enum nl80211_iftype iftype)
{
    if (iftype <= NL80211_IFTYPE_MAX && ifmodes[iftype])
        return ifmodes[iftype];
    sprintf(modebuf, "Unknown mode (%d)", iftype);
     return modebuf;
}


int ieee80211_frequency_to_channel(int freq)
{
    /* see 802.11-2007 17.3.8.3.2 and Annex J */
    if (freq == 2484)
        return 14;
    else if (freq < 2484)
        return (freq - 2407) / 5;
    else if (freq >= 4910 && freq <= 4980)
        return (freq - 4000) / 5;
    else if (freq <= 45000) /* DMG band lower limit */
        return (freq - 5000) / 5;
    else if (freq >= 58320 && freq <= 64800)
        return (freq - 56160) / 2160;
    else
        return 0;
}


unsigned long calc_crc_osdep(unsigned char *buf, int len)
{
    unsigned long crc = 0xFFFFFFFF;

    for (; len > 0; len--, buf++)
        crc = crc_tbl_osdep[(crc ^ *buf) & 0xFF] ^ (crc >> 8);

    return (~crc);
}

/* CRC checksum verification routine */

int check_crc_buf_osdep(unsigned char *buf, int len)
{
    unsigned long crc;

    if (len < 0) return 0;

    crc = calc_crc_osdep(buf, len);
    buf += len;
    return (((crc) &0xFF) == buf[0] && ((crc >> 8) & 0xFF) == buf[1]
            && ((crc >> 16) & 0xFF) == buf[2]
            && ((crc >> 24) & 0xFF) == buf[3]);
}


const char *channel_width_name(enum nl80211_chan_width width)
{
    switch (width) {
    case NL80211_CHAN_WIDTH_20_NOHT:
        return "20 MHz (no HT)";
    case NL80211_CHAN_WIDTH_20:
        return "20 MHz";
    case NL80211_CHAN_WIDTH_40:
        return "40 MHz";
    case NL80211_CHAN_WIDTH_80:
        return "80 MHz";
    case NL80211_CHAN_WIDTH_80P80:
        return "80+80 MHz";
    case NL80211_CHAN_WIDTH_160:
        return "160 MHz";
    case NL80211_CHAN_WIDTH_5:
        return "5 MHz";
    case NL80211_CHAN_WIDTH_10:
        return "10 MHz";
    default:
        return "unknown";
    }
}

const char *cipher_name(__u32 c)
{
    static char buf[20];

    switch (c) {
    case 0x000fac01:
        return "WEP40 (00-0f-ac:1)";
    case 0x000fac05:
        return "WEP104 (00-0f-ac:5)";
    case 0x000fac02:
        return "TKIP (00-0f-ac:2)";
    case 0x000fac04:
        return "CCMP-128 (00-0f-ac:4)";
    case 0x000fac06:
        return "CMAC (00-0f-ac:6)";
    case 0x000fac08:
        return "GCMP-128 (00-0f-ac:8)";
    case 0x000fac09:
        return "GCMP-256 (00-0f-ac:9)";
    case 0x000fac0a:
        return "CCMP-256 (00-0f-ac:10)";
    case 0x000fac0b:
        return "GMAC-128 (00-0f-ac:11)";
    case 0x000fac0c:
        return "GMAC-256 (00-0f-ac:12)";
    case 0x000fac0d:
        return "CMAC-256 (00-0f-ac:13)";
    case 0x00147201:
        return "WPI-SMS4 (00-14-72:1)";
    default:
        sprintf(buf, "%.2x-%.2x-%.2x:%d",
            c >> 24, (c >> 16) & 0xff,
            (c >> 8) & 0xff, c & 0xff);

        return buf;
    }
}


static const char *witoolspath[] = {
    "/sbin",
    "/usr/sbin",
    "/usr/local/sbin",
    "/bin",
    "/usr/bin",
    "/usr/local/bin",
    "/tmp",
};

static const int g_num_witoolspath = sizeof(witoolspath) / sizeof(const char *);

/*
 * is_ndiswrapper - 判定网卡接口是否为ndiswrapper
 *
 * NdisWrapper实际上是一个开源的驱动(从技术上讲,是内核的一个模块),
 * 它能够让Linux使用标准的Windows XP下的无线网络驱动.
 * 你可以认为NdisWrapper是Linux内核和Windows驱动之间的一个翻译层.
 * Windows驱动可以通过 NdisWrapper的配置工具进行安装
 *
 * @iface: 网卡接口
 * @path: iwpriv路径
 */
int is_ndiswrapper(const char *iface, const char *path)
{
    int n, pid;
    if (!path || !iface)
        return 0;

    if (0 == (pid = fork())) {
        close(0);
        close(1);
        close(2);
        chdir("/");
        execl(path, "iwpriv", iface, "ndis_reset", NULL);
        exit(1);
    }

    waitpid(pid, &n, 0);
    return ((WIFEXITED(n) && WEXITSTATUS(n) == 0));
}

/*
 * search_recursively - 在指定目录及其子目录下查找指定文件
 *
 * @dir:指定目录
 * @filename:指定文件
 */
const char *search_recursively(const char *dir, const char *filename)
{
    DIR *dp = opendir(dir);
    if (NULL == dp)
        return NULL;

    int len = strlen(filename);
    int lentot = strlen(dir) + 256 + 2;
    char *curfile = new char[lentot];

    struct dirent *ep;
    while (NULL != (ep = readdir(dp))) {
        memset(curfile, 0, lentot);
        sprintf(curfile, "%s/%s", dir, ep->d_name);

        if (len == (int)strlen(ep->d_name) && !strcmp(ep->d_name, filename)) {
            closedir(dp);
            return curfile;
        }

        struct stat sb;
        if (0 == lstat(curfile, &sb) && S_ISDIR(sb.st_mode) && !S_ISLNK(sb.st_mode)) {
            if (strcmp(".", ep->d_name)  && strcmp("..", ep->d_name)) {
                const char *ret = search_recursively(curfile, filename);
                if (NULL != ret) {
                    closedir(dp);
                    free(curfile);
                    return curfile;
                }
            }
        }
    }

    closedir(dp);
    free(curfile);
    return NULL;
}

const char *get_witool_path(const char *tool)
{
    const char *re;
    for (int i = 0; i < g_num_witoolspath; i++) {
        re = search_recursively(witoolspath[i], tool);
        if (NULL != re)
            return re;
    }

    return NULL;
}

void hide_cursor(void)
{
    char command[13];

    snprintf(command, sizeof(command), "%c[?25l", 0x1B);
    fprintf(stdout, "%s", command);
    fflush(stdout);
}





