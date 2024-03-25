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
    QHttpServerResponse checkingToken(const QHttpServerRequest &request) {

        QJsonWebToken token = Token.getAccesToken(request);
        QString strPayload = token.getPayloadQStr();
        QString idToken = Token.getIDtoken(strPayload);
        qDebug()<<strPayload;

        if (!token.isValid())
        {   QString mess = "Token is not validate , you need to login again!";
             return QHttpServerResponse(mess,QHttpServerResponse::StatusCode::Unauthorized);
        }
        if (Token.TimelifeTK(strPayload) == false)
        {
             QString mess = "Token is exprined, you need to login again!";
             return QHttpServerResponse(mess,QHttpServerResponse::StatusCode::Unauthorized);
        }
        if (Token.TokenInBlacklit(idToken))
        {
            QString mess = "Token is revoked, you need to login again!";
            return QHttpServerResponse(mess,QHttpServerResponse::StatusCode::Unauthorized);
        }
        return QHttpServerResponse(QHttpServerResponse::StatusCode::Continue);
};


private:
    TokenManager Token;
};

#endif // AUTHMIDDLEWARE_H
