#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QStandardItem>

#include <ByNetEngine.h>
#include <ByNetDev.h>

#include <iostream>
#include <thread>
#include <map>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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




