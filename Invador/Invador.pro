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
LIBS += -lnl-genl-3 -lnl-3

SOURCES += main.cpp\
        mainwindow.cpp \
    ByNetEngine.cpp \
    utils.cpp


HEADERS  += mainwindow.h \
    iw/ieee80211.h \
    iw/iw.h \
    iw/nl80211.h \
    iw/handle.h \
    ByNetEngine.h

FORMS    += mainwindow.ui
