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

    connect(&m_engine, SIGNAL(WpaCaptured(ByNetMacAddr)), this, SLOT(mEngine_WpaCaptured(ByNetMacAddr)));
    connect(&m_engine, SIGNAL(FoundNewAp()), this, SLOT(mEngine_NewAp()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::mEngine_WpaCaptured(ByNetMacAddr bssid)
{
    std::cout << "captured wpa:";
    bssid.Print();

    ByNetCntInfo *cnt = m_engine.GetCntInfo();
    ByNetApInfo *ap = cnt->FindAp(bssid.GetValue());

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

    std::cout << std::endl;
}

void MainWindow::mEngine_NewAp()
{
    ByNetCntInfo *cnt = m_engine.GetCntInfo();

    std::cout << "num ap:" << cnt->GetApMap().size() << std::endl;

    delete cnt;
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



ByNetApInfo *MainWindow::read_cap_file(const char *filename, uint8_t *bssid)
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

        ap_cur = m_engine.ParsePacket(buffer, pkh.caplen);

        if (0 != ap_cur && ap_cur->gotwpa) {
            /* got one valid handshake */
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
        getmac("EC:17:2F:1A:00:52", 1, __bssid);
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



