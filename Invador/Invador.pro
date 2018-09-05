#-------------------------------------------------
#
# Project created by QtCreator 2018-07-09T14:41:47
#
#-------------------------------------------------

QT       += core gui widgets

TARGET = Invador
TEMPLATE = app

DEFINES += CONFIG_LIBNL30
INCLUDEPATH += /usr/include/libnl3
INCLUDEPATH += ./iw
INCLUDEPATH += ./radiotap
INCLUDEPATH += ./aircrack-util
INCLUDEPATH += ./aircrack-osdep
INCLUDEPATH += ./ByNet
LIBS += -lnl-genl-3 -lnl-3

SOURCES += main.cpp\
        mainwindow.cpp \
    utils.cpp \
    radiotap/radiotap.cpp \
    aircrack-util/verifyssid.cpp \
    aircrack-util/mcs_index_rates.cpp \
    uniqueiv.cpp \
    aircrack-osdep/common.cpp \
    aircrack-util/common_util.cpp \
    ByNet/ByNetDev.cpp \
    ByNet/ByNetEngine.cpp \
    ByNet/ByNetInterface.cpp


HEADERS  += mainwindow.h \
    iw/ieee80211.h \
    iw/iw.h \
    iw/nl80211.h \
    iw/handle.h \
    utils.h \
    radiotap/radiotap.h \
    radiotap/radiotap_iter.h \
    byteorder.h \
    crctable_osdep.h \
    pcap.h \
    eapol.h \
    crypto.h \
    aircrack-util/verifyssid.h \
    aircrack-util/mcs_index_rates.h \
    uniqueiv.h \
    aircrack-osdep/common.h \
    aircrack-util/common_util.h \
    ByNet/ByNetDev.h \
    ByNet/ByNetEngine.h \
    ByNet/ByNetInterface.h

FORMS    += mainwindow.ui
