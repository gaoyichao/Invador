#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItemModel>

#include <ByNetEngine.h>
#include <ByNetDev.h>

#include <map>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_mDevPushButton_clicked();

    void on_mDevPushButton_2_clicked();

    void on_mDevPushButton_3_clicked();

private:
    Ui::MainWindow *ui;
    BYNetEngine m_engine;
};

#endif // MAINWINDOW_H
