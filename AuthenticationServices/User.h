#ifndef USER_H
#define USER_H

#include <QObject>
#include <QJsonDocument>
#include <QHttpServer>
#include "DatabaseConnection.h"
#include "TokenManager.h"

class User : public QObject {
    Q_OBJECT

public:
    User();
    QHttpServerResponse Login_for_O2(const QHttpServerRequest &request);
    QHttpServerResponse Login_for_O1(const QHttpServerRequest &request);
    QHttpServerResponse handleRereshToken(const QHttpServerRequest &request);
    QHttpServerResponse Logout_o2(const QHttpServerRequest &request);
    QHttpServerResponse Logout_o1(const QHttpServerRequest &request);
    QHttpServerResponse Example(const QHttpServerRequest &request);

private:
    QSqlDatabase db;
    TokenManager Token;

    bool authenticateUser(const QString &username, const QString &password);
    QString getUserIdByUsername(const QString &username);
    QString hashPassword(const QString &password);
    bool hasContentType(const QHttpServerRequest &request);
    QHttpServerResponse ResponseWithTokens(const QString &userID);
    QHttpServerResponse ResponseWithOauth1Tokens(const QString &userID);
    QHttpServerResponse ErrorResponse(const QString &errorMessage, const QString &errorDetail);
    bool checkInvalidate(const QString &token_id, const QString &token, const QString &userID);
    bool remove_refreshtoken_Oauth2(const QString &UserId, const QString &token_id);
};

#endif // USER_H
