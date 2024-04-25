#ifndef AUTHMIDDLEWARE_H
#define AUTHMIDDLEWARE_H
#include "TokenManager.h"
#include "qjsonobject.h"
#include <QHttpServer>
#include <QHttpServerResponse>
#include <QtCore/QCoreApplication>
#include <QtHttpServer/QHttpServer>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QVariant>
#include <QCryptographicHash>
#include <qjsonwebtoken.h>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>
#include <QSettings>
#include "TokenManager.h"


class Middleware {
public:

    QHttpServerResponse checkingToken_O1(const QHttpServerRequest &request);
    QHttpServerResponse checkingToken_O2(const QHttpServerRequest &request);

private:
    TokenManager Token;

};

#endif // AUTHMIDDLEWARE_H
