#ifndef AUTHENTICATIONMANAGER_H
#define AUTHENTICATIONMANAGER_H

#include <QObject>
#include <QJsonDocument>
#include <QHttpServer>
#include "DatabaseConnection.h"
#include "TokenManager.h"
#include "User.h"

class AuthenticationManager : public QObject {
    Q_OBJECT

public:

    AuthenticationManager();
    QHttpServerResponse Login_for_O2(const QHttpServerRequest &request);
    QHttpServerResponse Login_for_O1(const QHttpServerRequest &request);
    QHttpServerResponse handleRereshToken(const QHttpServerRequest &request);
    QHttpServerResponse Logout_o2(const QHttpServerRequest &request);
    QHttpServerResponse Logout_o1(const QHttpServerRequest &request);
    QHttpServerResponse Example(const QHttpServerRequest &request);

private:

    QSqlDatabase db;
    TokenManager Token;


    // bool authenticateUser(const QString &username, const QString &password);
    // QString getUserIdByUsername(const QString &username);
    // QString hashPassword(const QString &password);

    bool hasContentType(const QHttpServerRequest &request);
    QHttpServerResponse ResponseWithTokens(const QString &userID);
    QHttpServerResponse ResponseWithOauth1Tokens(const QString &userID);
    QHttpServerResponse ErrorResponse(const QString &errorMessage, const QString &errorDetail);
};

#endif // AUTHENTICATIONMANAGER_H
