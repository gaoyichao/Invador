#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QStandardItem>
#include <QMessageBox>
#include <QFileDialog>

#include <ByNetEngine.h>
#include <ByNetCrypto.h>
#include <ByNetDev.h>

#include <iostream>
#include <thread>
#include <map>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <utils.h>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    m_engine.ClearDevs();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_mDevPushButton_clicked()
{
    auto devs = m_engine.UpdateDevs();

    std::cout << ">>> " << std::endl;
    std::cout << ">>> num of devs:" << devs.size() << std::endl;
    for (auto it = devs.begin(); it != devs.end(); it++) {
        ByNetDev *dev = &(it->second);
        auto interfaceMap = dev->GetAllInterfaces();
        std::cout << ">>> num of interfaces:" << interfaceMap.size() << std::endl;
        for (auto infit = interfaceMap.begin(); infit != interfaceMap.end(); infit++) {
            std::cout << ">>> " << infit->second.GetIfName() << std::endl;
        }
    }
}



void MainWindow::on_mDevPushButton_2_clicked()
{
    auto devs = m_engine.UpdateDevs();

    std::cout << ">>> " << std::endl;
    std::cout << ">>> num of devs:" << devs.size() << std::endl;
    for (auto it = devs.begin(); it != devs.end(); it++) {
        ByNetDev *dev = &(it->second);
        std::cout << ">>> # supported ciphers:" << dev->GetSupportedCiphers().size() << std::endl;
        std::cout << ">>> # supported if types:" << dev->GetSupportedIfTypes().size() << std::endl;
        std::cout << ">>> # cmd:" << dev->GetSupportedCmd().size() << std::endl;
    }
}

void MainWindow::on_mDevPushButton_3_clicked()
{
    m_moninterface = m_engine.FindMonitorInterface();

    if (NULL == m_moninterface) {
        m_engine.prepare(CIB_PHY, 0);
        m_engine.handle_cmd(0, NL80211_CMD_NEW_INTERFACE, handle_interface_add, NULL);
    }

    m_moninterface = m_engine.FindMonitorInterface();
    if (NULL != m_moninterface) {
        std::cout << ">>> monitor interface:" << m_moninterface->GetIfName() << std::endl;
        std::cout << ">>> monitor interface id:" << m_moninterface->GetIfIndex() << std::endl;
    }
}

void MainWindow::on_mDevPushButton_4_clicked()
{
    QString ifname = ui->lineEdit->text();
    signed long long devidx = if_nametoindex(ifname.toStdString().c_str());
    std::cout << "devidx:" << devidx << std::endl;

    if (devidx < 0)
        return;

    m_engine.prepare(CIB_NETDEV, devidx);
    m_engine.handle_cmd(0, NL80211_CMD_DEL_INTERFACE, handle_interface_del, NULL);
}

#define REFRESH_RATE 100000

void MainWindow::on_mDevPushButton_5_clicked()
{
    if (NULL == m_engine.get_dump_file()) {
        QString filename = QFileDialog::getSaveFileName(this, "文件另存为", "", tr("Recved Data (*.cap)"));
        m_engine.init_dump_file(filename.toStdString().c_str());
        ui->mDevPushButton_5->setText("关闭文件");
    } else {
        m_engine.close_dump_file();
        ui->mDevPushButton_5->setText("打开文件");
    }


}

void MainWindow::on_mDevPushButton_6_clicked()
{
    if (m_engine.is_moniting()) {
        m_engine.stop_monite();
        ui->mDevPushButton_6->setText("开始监听");
    } else {
        try {
            m_engine.start_monite();
            ui->mDevPushButton_6->setText("停止监听");
        } catch (const char *msg) {
            QMessageBox::critical(this, "Error", msg);
            exit(1);
        }
    }
}

#include <dlfcn.h>
#include <trampoline.h>
#include <aircrack-util/common_util.h>
#include <aircrack-util/avl_tree.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <crypto.h>
#include <uniqueiv.h>

static int station_compare(const void *a, const void *b)
{
    return memcmp(a, b, 6);
}
c_avl_tree_t *access_points = NULL;
c_avl_tree_t *targets = NULL;

void destroy_ap(ByNetApInfo *ap)
{
    if (0 != ap->ivbuf)
        free(ap->ivbuf);

    free(ap);
}

ByNetApInfo *read_cap_file(const char *filename, uint8_t *bssid)
{
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
        throw "could not open the cap file!";

    struct pcap_file_header pfh;
    if (24 != read(fd, &pfh, 24))
        throw "read(file header) failed!";

    printf("magic:%x\n", pfh.magic);
    if (pfh.magic != TCPDUMP_MAGIC)
        throw "unsupported file format!";

    if (pfh.linktype != LINKTYPE_IEEE802_11
        && pfh.linktype != LINKTYPE_PRISM_HEADER
        && pfh.linktype != LINKTYPE_RADIOTAP_HDR
        && pfh.linktype != LINKTYPE_PPI_HDR)
        throw "This file is not a regular 802.11 (wireless) capture.";

    uint8_t *buffer = (uint8_t*)malloc(65536);
    unsigned z;
    ByNetApInfo *ap_cur = 0;
    ByNetStInfo *st_cur;

    while (1) {
        struct pcap_pkthdr pkh;
        if (sizeof(pkh) != read(fd, &pkh, sizeof(pkh)))
            break;

        if (pkh.caplen <= 0 || pkh.caplen > 65535)
            throw "Invalid packet capture length, corrupted file?";

        if (0 == buffer)
            throw "malloc failed";

        if (pkh.caplen != read(fd, buffer, pkh.caplen))
            throw "Invalid packet capture length, corrupted file?";

        uint8_t *h80211 = buffer;
        uint8_t *p = NULL;

        if (pkh.caplen < 24)
            continue;
        if (0x04 == (h80211[0] & 0x0C))
            continue;

        unsigned char bssid_tmp[6];
        unsigned char dest[6];
        unsigned char stmac[6];

        switch (h80211[1] & 3) {
        case 0:
            memcpy(bssid_tmp, h80211 + 16, 6);
            memcpy(dest, h80211 + 4, 6);
            break; //Adhoc
        case 1:
            memcpy(bssid_tmp, h80211 + 4, 6);
            memcpy(dest, h80211 + 16, 6);
            break; //ToDS
        case 2:
            memcpy(bssid_tmp, h80211 + 10, 6);
            memcpy(dest, h80211 + 4, 6);
            break; //FromDS
        case 3:
            memcpy(bssid_tmp, h80211 + 10, 6);
            memcpy(dest, h80211 + 16, 6);
            break; //WDS -> Transmitter taken as BSSID
        }


        if (0 == memcmp(bssid_tmp, BROADCAST, 6))
            continue;

        if (0 != memcmp(bssid_tmp, bssid, 6))
            continue;

        int not_found = c_avl_get(access_points, bssid_tmp, (void**)&ap_cur);
        if (not_found) {
            ap_cur = new ByNetApInfo(bssid_tmp);
            if (0 == ap_cur)
                throw "failed to alloc ap_cur";

            ap_cur->crypt = 3;

            c_avl_insert(access_points, bssid_tmp, ap_cur);
        }

        st_cur = NULL;
        switch (h80211[1] & 3) {
        case 0:
            memcpy(stmac, h80211 + 10, 6);
            break;
        case 1:
            memcpy(stmac, h80211 + 10, 6);
            break;
        case 2:
            /* reject broadcast MACs */
            if ((h80211[4] % 2) != 0)
                goto skip_station;
            memcpy(stmac, h80211 + 4, 6);
            break;
        default:
            goto skip_station;
            break;
        }

        st_cur = ap_cur->FindStation(stmac);
        if (!st_cur)
            st_cur = ap_cur->AddStation(stmac);
        std::cout << ">>> st_cur" << std::endl;
        if (!st_cur)
            throw "malloc st_cur failed!";

skip_station:
        /* packet parsing: Beacon or Probe Response */
        if (h80211[0] == 0x80 || h80211[0] == 0x50) {
            p = h80211 + 36;
            while (p < h80211 + pkh.caplen) {
                if (p + 2 + p[1] > h80211 + pkh.caplen)
                    break;

                if (0x00 == p[0] && p[1] > 0 && p[2] != '\0') {
                    /* found a non-cloaked ESSID */
                    int n = (p[1] > 32) ? 32 : p[1];
                    std::cout << "Beacon p[1] = " << n << std::endl;
                    memset(ap_cur->essid, 0, 33);
                    memcpy(ap_cur->essid, p+2, n);
                }
                p += 2 + p[1];
            }
        }

        /* packet parsing: Association Request */
        if (h80211[0] == 0x00) {
            p = h80211 + 28;

            while (p < h80211 + pkh.caplen) {
                if (p + 2 + p[1] > h80211 + pkh.caplen)
                    break;

                if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0') {
                    int n = (p[1] > 32) ? 32 : p[1];

                    std::cout << "Association Request p[1] = " << p[1] << std::endl;
                    memset(ap_cur->essid, 0, 33);
                    memcpy(ap_cur->essid, p + 2, n);
                }
                p += 2 + p[1];
            }
        }

        /* packet parsing: Association Response */
        if (h80211[0] == 0x10) {
            /* reset the WPA handshake state */
            if (st_cur != NULL)
                st_cur->wpa.state = 0;
            std::cout << "Reset Response!!!" << std::endl;
        }

        /* check if data */
        if ((h80211[0] & 0x0C) != 0x08)
            continue;

        /* check minimum size */
        z = ((h80211[1] & 3) != 3) ? 24 : 30;
        if ((h80211[0] & 0x80) == 0x80)
            z += 2; /* 802.11e QoS */
        if (z + 16 > pkh.caplen)
            continue;

        /* no encryption */
        if (ap_cur->crypt < 0)
            ap_cur->crypt = 0;

        z += 6;
        if (z + 20 < pkh.caplen) {
            if (h80211[z] == 0x08 && h80211[z + 1] == 0x00 && (h80211[1] & 3) == 0x01)
                memcpy(ap_cur->lanip, &h80211[z + 14], 4);

            if (h80211[z] == 0x08 && h80211[z + 1] == 0x06)
                memcpy(ap_cur->lanip, &h80211[z + 16], 4);
        }

        /* check ethertype == EAPOL */
        if (h80211[z] != 0x88 || h80211[z + 1] != 0x8E)
            continue;
        z += 2;
        ap_cur->eapol = 1;

        /* type == 3 (key), desc. == 254 (WPA) or 2 (RSN) */
        if (h80211[z + 1] != 0x03 || (h80211[z + 4] != 0xFE && h80211[z + 4] != 0x02))
            continue;
        ap_cur->eapol = 0;
        ap_cur->crypt = 3; /* set WPA */
        if (NULL == st_cur) {
            destroy_ap(ap_cur);
            ap_cur = 0;
            continue;
        }

        /* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */
        if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
            && (h80211[z + 6] & 0x80) != 0 && (h80211[z + 5] & 0x01) == 0) {
            memcpy(st_cur->wpa.anonce, &h80211[z + 17], 32);
            /* authenticator nonce set */
            st_cur->wpa.state = 1;
            std::cout << "frame 1" << std::endl;
        }

        /* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */
        if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
            && (h80211[z + 6] & 0x80) == 0 && (h80211[z + 5] & 0x01) != 0) {
            if (memcmp(&h80211[z + 17], ZERO, 32) != 0) {
                memcpy(st_cur->wpa.snonce, &h80211[z + 17], 32);
                /* supplicant nonce set */
                st_cur->wpa.state |= 2;
            }

            if (4 != (st_cur->wpa.state & 4)) {
                /* copy the MIC & eapol frame */
                st_cur->wpa.eapol_size = (h80211[z + 2] << 8) + h80211[z + 3] + 4;
                if (st_cur->wpa.eapol_size == 0 || st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol) || pkh.len - z < st_cur->wpa.eapol_size)
                {
                    // Ignore the packet trying to crash us.
                    st_cur->wpa.eapol_size = 0;
                    continue;
                }
                memcpy(st_cur->wpa.keymic, &h80211[z + 81], 16);
                memcpy(st_cur->wpa.eapol, &h80211[z], st_cur->wpa.eapol_size);
                memset(st_cur->wpa.eapol + 81, 0, 16);

                /* eapol frame & keymic set */
                st_cur->wpa.state |= 4;
                /* copy the key descriptor version */
                st_cur->wpa.keyver = h80211[z + 6] & 7;
            }

            std::cout << "frame 2 or 4" << std::endl;
        }
        /* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */
        if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) != 0
            && (h80211[z + 6] & 0x80) != 0 && (h80211[z + 5] & 0x01) != 0) {
            if (memcmp(&h80211[z + 17], ZERO, 32) != 0) {
                memcpy(st_cur->wpa.anonce, &h80211[z + 17], 32);
                /* authenticator nonce set */
                st_cur->wpa.state |= 1;
            }

            if ((st_cur->wpa.state & 4) != 4) {
                /* copy the MIC & eapol frame */
                st_cur->wpa.eapol_size = (h80211[z + 2] << 8) + h80211[z + 3] + 4;

                if (st_cur->wpa.eapol_size == 0 || st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol) || pkh.len - z < st_cur->wpa.eapol_size) {
                    // Ignore the packet trying to crash us.
                    st_cur->wpa.eapol_size = 0;
                    continue;
                }

                memcpy(st_cur->wpa.keymic, &h80211[z + 81], 16);
                memcpy(st_cur->wpa.eapol, &h80211[z], st_cur->wpa.eapol_size);
                memset(st_cur->wpa.eapol + 81, 0, 16);

                /* eapol frame & keymic set */
                st_cur->wpa.state |= 4;

                /* copy the key descriptor version */
                st_cur->wpa.keyver = h80211[z + 6] & 7;
            }
        }

        if (st_cur->wpa.state == 7) {
            /* got one valid handshake */
            memcpy(st_cur->wpa.stmac, stmac, 6);
            memcpy(&ap_cur->wpa, &st_cur->wpa, sizeof(struct WPA_hdsk));
            std::cout << "got one valid handshake" << std::endl;
            break;
        }
    }

    if (0 != buffer)
        free(buffer);
    return ap_cur;
}

#include <stdio.h>
void MainWindow::on_mDevPushButton_7_clicked()
{
    try {
        access_points = c_avl_create(station_compare);
        targets = c_avl_create(station_compare);

        unsigned char __bssid[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        getmac("02:1A:11:FC:C5:93", 1, __bssid);
        ByNetApInfo *ap = read_cap_file("tu-04.cap", __bssid);

        std::cout << "n ap = " << c_avl_size(access_points) << std::endl;
        std::cout << "n targets = " << c_avl_size(targets) << std::endl;
        printf(">>> ap->wpa.keyver:%x\n", ap->wpa.keyver);

        ByNetCrypto crypto;
        __u8 mic[20] __attribute__((aligned(32)));
        crypto.SetESSID(ap->essid);
        crypto.CalPke(ap->bssid, ap->wpa.stmac, ap->wpa.anonce, ap->wpa.snonce);
        std::string tmp("nuaabuaa");
        crypto.CalPmk((__u8*)tmp.c_str());
        crypto.CalPtk();
        crypto.CalMic(ap->wpa.eapol, ap->wpa.eapol_size, mic);

        if (0 == memcmp(mic, ap->wpa.keymic, 16))
            std::cout << "catch you!!" << std::endl;

        std::cout << crypto.GetESSID() << std::endl;
        std::cout << crypto.GetESSIDLen() << std::endl;

    } catch (const char *msg) {
        QMessageBox::critical(this, "Error", msg);
        exit(1);
    }
}



