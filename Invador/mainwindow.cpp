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
    ByNetInterface const *interface = m_engine.FindMonitorInterface();

    if (NULL == interface) {
        m_engine.prepare(CIB_PHY, 0);
        m_engine.handle_cmd(0, NL80211_CMD_NEW_INTERFACE, handle_interface_add, NULL);
    }

    interface = m_engine.FindMonitorInterface();
    if (NULL != interface)
        std::cout << ">>> monitor interface:" << interface->GetIfName() << std::endl;
}



