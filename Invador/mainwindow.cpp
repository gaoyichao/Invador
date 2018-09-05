#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QStandardItem>
#include <QMessageBox>

#include <ByNetEngine.h>
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
    m_moninterface = m_engine.FindMonitorInterface();
    if (NULL == m_moninterface)
        return;

    //m_moninterface->open();
    try {
        m_moninterface->Open();

        int fd_raw = m_moninterface->GetFd();
        int fdh = 0;
        if (fd_raw > fdh)
            fdh = fd_raw;

        fd_set rfds;
        struct timeval tv0;
        unsigned char buffer[4096];
        struct rx_info ri;
        int read_failed_count = 0;

        while (1) {
            FD_ZERO(&rfds);
            FD_SET(fd_raw, &rfds);
            tv0.tv_sec = 0;
            tv0.tv_usec = REFRESH_RATE;
            select(fdh+1, &rfds, NULL, NULL, &tv0);

            if (FD_ISSET(fd_raw, &rfds)) {
                memset(buffer, 0, sizeof(buffer));
                int caplen = m_moninterface->Read(buffer, sizeof(buffer), &ri);
                if (-1 == caplen) {
                    read_failed_count++;
                    std::cerr << ">>> Read Failed!!! " << read_failed_count << std::endl;
                } else {
                    read_failed_count = 0;
                    m_moninterface->DumpPacket(buffer, caplen, &ri, NULL);
                }
            }
        }
    } catch (const char *msg) {
        QMessageBox::critical(this, "Error", msg);
        exit(1);
    }
}





