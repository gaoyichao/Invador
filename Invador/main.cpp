#include "mainwindow.h"
#include <QApplication>

#include <iostream>
#include <string>

#include <unistd.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include <nl80211.h>
#include <iw.h>

#include <ByNetEngine.h>


int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        std::cout << "需要root权限!!" << std::endl;
        return 1;
    }


    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}
