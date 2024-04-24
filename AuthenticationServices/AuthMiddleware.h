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

QHttpServerResponse checkingToken_O1(const QHttpServerRequest &request)
{
    QList<std::pair<QByteArray, QByteArray>> headers = request.headers();

    //Lấy Access token O1 từ header

    QString accessToken_o1 = Token.extractToken_o1(headers);
    if(accessToken_o1 == "")
    {
        QString mess = "Access token not found in header, you need to try again!";
        return QHttpServerResponse(mess,QHttpServerResponse::StatusCode::Unauthorized);
    }
    QStringList listJwtParts = accessToken_o1.split(".");
    if (listJwtParts.count() != 3)
        {
            return QHttpServerResponse("invalid_request", "token must have the format xxxx.yyyyy.zzzzz",QHttpServerResponse::StatusCode::Unauthorized);
        }
    QJsonWebToken token = Token.getAccesToken_01(accessToken_o1);
    QString exp = token.claim("exp");
    QString iat = token.claim("iat");

    //kiểm tra tính validate của token
    if (!token.isValid())
        {   QString mess = "Token is not validate , you need to login again!";
            return QHttpServerResponse(mess,QHttpServerResponse::StatusCode::Unauthorized);
        }
    //kiểm tra access token có trong blacklist hay không?
    if (Token.TokenInBlacklit(iat))
        {
            QString mess = "This token has been revoked , you need to login again!";
            return QHttpServerResponse(mess,QHttpServerResponse::StatusCode::Unauthorized);
        }
    // Kiểm tra thời gian sống của token
    if (Token.TimelifeTK(exp) == false)
        {
            QString mess = "Token is exprined, you need to login again!";
            return QHttpServerResponse(mess,QHttpServerResponse::StatusCode::Unauthorized);
        }

    qDebug()<<"Access token is correct";
    return QHttpServerResponse(QHttpServerResponse::StatusCode::Continue);

}

QHttpServerResponse checkingToken_O2(const QHttpServerRequest &request)
    {

    QList<std::pair<QByteArray, QByteArray>> headers = request.headers();
    //Lấy token từ header
    QString accessToken_o2 = Token.extractToken_o2(headers);
    QStringList listJwtParts = accessToken_o2.split(".");
    // Kiểm tra có lấy được giá trị token từ header hay k?
    if(accessToken_o2 == "")
    {
        QString mess = "Access token not found in header, you need to try again!";
        return QHttpServerResponse(mess,QHttpServerResponse::StatusCode::Unauthorized);
    }
    // Kiểm tra định dạng của token
    if (listJwtParts.count() != 3)
        {
            return QHttpServerResponse("invalid_request", "token must have the format xxxx.yyyyy.zzzzz",QHttpServerResponse::StatusCode::Unauthorized);
        }
    QJsonWebToken token = Token.getAccesToken_o2(accessToken_o2);
    QString exp = token.claim("exp");
        // Kiểm tra validate của token
        if (!token.isValid())
        {   QString mess = "Token is not validate , you need to login again!";
            return QHttpServerResponse(mess,QHttpServerResponse::StatusCode::Unauthorized);
        }
        // Kiểm tra time sống của token
        if (Token.TimelifeTK(exp) == false)
        {
            QString mess = "Token is exprined, you need to login again!";
            return QHttpServerResponse(mess,QHttpServerResponse::StatusCode::Unauthorized);
        }

        qDebug()<<"Access token is correct";
        return QHttpServerResponse(QHttpServerResponse::StatusCode::Continue);

};

private:
    TokenManager Token;

};

#endif // AUTHMIDDLEWARE_H
