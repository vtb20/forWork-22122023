#ifndef TOKENMANAGER_H
#define TOKENMANAGER_H

#include <qjsonwebtoken.h>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>
#include <QSettings>
#include <qjsonwebtoken.h>
#include <QtHttpServer/QHttpServer>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QSqlError>
#include "DatabaseConnection.h"
#include <QTimer>
#include <QPair>
#include <QString>
#include <QMap>
#include <QObject>
#include <QByteArray>
#include <QDateTime>
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>


class TokenManager : public QObject {
    Q_OBJECT

public:
    TokenManager();
    QString createAccessToken(const QString &userID, const QString &version);
    QString createRFtoken(const QString &userID, const QString &exp = "");
    bool TimelifeTK(const QString &expValue);
    QJsonWebToken getRFtk(const QString &Refreshtokn);
    QJsonWebToken getAccesToken_o2(const QString &accessToken);
    QJsonWebToken getAccesToken_01(const QString &accessToken);
    QByteArray extractToken_o2(const QList<std::pair<QByteArray, QByteArray>> &headers);
    QByteArray extractToken_o1(const QList<std::pair<QByteArray, QByteArray>> &headers);
    QString getSecretKeyrftk();
    bool addTKBlacklist(const QString &idToken, QString &expTime);
    bool TokenInBlacklit(const QString &IDtoken);
    QString checkingTypeTOKEN(const QList<std::pair<QByteArray, QByteArray>> &headers);

private:
    QSqlDatabase db;
    QTimer *cleanupBLTimer;
    QString generateTokenId(const QString &userID);
    void removeExpiredTokens();
};

#endif
