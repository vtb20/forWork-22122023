#ifndef OAUTHCLIENT_H
#define OAUTHCLIENT_H

#include <QObject>
#include <QDebug>
#include <QUrlQuery>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QEventLoop>
#include "o2.h"

class OAuthClient : public QObject
{
    Q_OBJECT

public:
    explicit OAuthClient(QObject *parent = nullptr);

private slots:
    void onLinkedChanged();
    void getData();

private:
    QNetworkAccessManager *manager;
    O2 *o2;
};

#endif // OAUTHCLIENT_H
