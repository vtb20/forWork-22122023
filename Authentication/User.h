#ifndef USER_H
#define USER_H

#include "qjsonobject.h"
#include <QJsonDocument>
#include <QObject>
#include <QJsonObject>
#include <QHttpServer>
#include <QHttpServerResponse>
#include <QtCore/QCoreApplication>
#include <QtHttpServer/QHttpServer>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QVariant>
#include <QCryptographicHash>
#include <QSettings>
#include <QRegularExpression>
#include <QDebug>
#include <QUrlQuery>
#include <qjsonwebtoken.h>
#include <QTimer>
#include "DatabaseConnection.h"
#include "TokenManager.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QSqlRecord>

class User:public QObject {
    Q_OBJECT

public:
    User() : db(DatabaseConnection::connect()) {}

    // Xử lý đăng ký user cho client
    QHttpServerResponse Register(const QHttpServerRequest &request) {
        QJsonDocument jsonDoc = QJsonDocument::fromJson(request.body());
        QJsonObject jsonObj = jsonDoc.object();

        QString username = jsonObj.value("username").toString();
        QString email = jsonObj.value("email").toString();
        QString password = jsonObj.value("password").toString();

        if (password.length() < 6 || password.length() > 20) {
            return QHttpServerResponse("Invalid password length",QHttpServerResponse::StatusCode::BadRequest);
        }
        QString hashedPassword = hashPassword(password);
        if (username.length() < 6 || username.length() > 15 )
        {
            return QHttpServerResponse("Invalid username length",QHttpServerResponse::StatusCode::BadRequest);
        }
        if (email.length()< 10)
        {
            return QHttpServerResponse("Invalid email length",QHttpServerResponse::StatusCode::BadRequest);
        }
        if (addNewUser(username, email, hashedPassword)) {
            return QHttpServerResponse("Registration successful",QHttpServerResponse::StatusCode::Ok);
        } else {
            return QHttpServerResponse("Failed to register user",QHttpServerResponse::StatusCode::BadRequest);
        }
    };

    //Hàm Xử lý Authorization request
    QHttpServerResponse HandleTokenRequest(const QHttpServerRequest &request) {
        QByteArray data = request.body();
        QString grantType;
        QString username;
        QString password;
        QString client_id;

        QUrlQuery urlQuery(QString::fromUtf8(data));
        grantType = urlQuery.queryItemValue("grant_type");
        client_id = urlQuery.queryItemValue("client_id");

        // kiểm tra sự tồn tại của grant_type và content_type
        if(hasContentType(request)==false || data.isEmpty() ||grantType.isEmpty() || client_id.isEmpty() )
        {
            return ErrorResponse("invalid request!","Missing requied parameter or wrong content-type!");
        }

        // Xử lý cho resource owner password
        if (grantType == "password") {
            username = urlQuery.queryItemValue("username");
            password = urlQuery.queryItemValue("password");
            if(username.isEmpty()||password.isEmpty())
            {
                return ErrorResponse("invalid_request","Missing username or password");
            }
            bool isAuthenticated = authenticateUser(username, password);
            if (isAuthenticated) {
                QString userID = getUserIdByUsername(username);
                return ResponseWithTokens(userID);
            } else {
                return ErrorResponse("invalid_request","Sai tên đăng nhập hoặc mật khẩu");
            }
        }
        // Xử lý authorization code
        else if (grantType == "authorization_code") {
            return QHttpServerResponse(QHttpServerResponse::StatusCode::Ok);
       } else if (grantType == "client_credentials") {
            // Xử lý client credentials
            return QHttpServerResponse(QHttpServerResponse::StatusCode::Ok);
        } else if (grantType == "urn:ietf:params:oauth:grant-type:device_code") {
            // Xử lý device code
            return QHttpServerResponse(QHttpServerResponse::StatusCode::Ok);
        } else if (grantType == "refresh_token") {
            // Xử lý refresh token
            return QHttpServerResponse(QHttpServerResponse::StatusCode::Ok);
        } else {
            // Trường hợp grant_type không hợp lệ
            return ErrorResponse("invalid_request","unsupported_grant_type");
        }
    }

    //Hàm phản hồi access token
    QHttpServerResponse ResponseWithTokens(const QString &userID) {
        QString token = Token.createAccessToken(userID);
        QString rfToken = Token.createRFtoken(userID);

        QJsonObject jsonResponse;
        jsonResponse["access_token"] = token;
        jsonResponse["refresh_token"] = rfToken;
        jsonResponse["token_type"] = "Bearer";
        jsonResponse["expires_in"] = 7200;

        QJsonDocument jsonResponseDoc(jsonResponse);
        QByteArray responseBody = jsonResponseDoc.toJson();
        return QHttpServerResponse("application/json", responseBody, QHttpServerResponse::StatusCode::Ok);
    }
    // Hàm khởi tạo thông báo lỗi
    QHttpServerResponse ErrorResponse(const QString &errorMessage,const QString &errorDetail) {
        QJsonObject jsonResponse;
        jsonResponse["error"] = errorMessage;
        jsonResponse["error_description"] = errorDetail;

        QJsonDocument jsonResponseDoc(jsonResponse);
        QByteArray responseBody = jsonResponseDoc.toJson();
        return QHttpServerResponse("application/json", responseBody, QHttpServerResponse::StatusCode::Unauthorized);
    }
     // hàm xử lý call API từ user
    QHttpServerResponse Example(const QHttpServerRequest &request) {
        qDebug()<<request.headers();
        QSqlQuery query(db);

        if (!query.exec("SELECT name FROM users")) {
            // Xử lý lỗi khi thực hiện truy vấn
            return ErrorResponse("Query execution error", query.lastError().text());
        }

        QJsonArray jsonArray;
        while (query.next()) {
            QJsonObject jsonObject;
            QSqlRecord record = query.record();
            for (int i = 0; i < record.count(); ++i) {
                jsonObject[record.fieldName(i)] = QJsonValue::fromVariant(record.value(i));
            }
            jsonArray.append(jsonObject);
        }

        QJsonDocument jsonDocument(jsonArray);
        QByteArray jsonData = jsonDocument.toJson();
        // Trả cho client thông tin về tên của các user
        return QHttpServerResponse("application/json", jsonData, QHttpServerResponse::StatusCode::Ok);
    }


    //Xử lý Logout
    QHttpServerResponse Logout(const QHttpServerRequest &request) {
        // Lấy AccessToken từ request
        QJsonWebToken acToken = Token.getAccesToken(request);
        QString Payload = acToken.getPayloadQStr();
        // Tìm giá trị "sub" trong Payload
        QString userID = "";
        QString jti = "";
        QString exp = "";
        QJsonObject payloadObj = QJsonDocument::fromJson(Payload.toUtf8()).object();

        if (payloadObj.contains("sub")) {
            userID = payloadObj["sub"].toString();
        } else {
            // Trường hợp "sub" không tồn tại trong Payload
            QString mes = "Payload is invalid!";
            return QHttpServerResponse(mes, QHttpServerResponse::StatusCode::BadRequest);
        }
        if (payloadObj.contains("jti")) {
            jti = payloadObj["jti"].toString();
        }

        if (payloadObj.contains("exp")) {
            exp = payloadObj["exp"].toString();
        }

           // Kiểm tra xem RefreshToken tương ứng với userID có tồn tại không
        QSqlQuery query(db);
        query.prepare("SELECT * FROM refresh_tokens WHERE user_id = :userID");
        query.bindValue(":userID", userID);
        if (!query.exec()) {
            qDebug() << "Query failed:" << query.lastError().text();
            QString mes = "Database query failed!";
            return QHttpServerResponse(mes, QHttpServerResponse::StatusCode::InternalServerError);
        }

        if (query.next()) {
            // Xóa refresh token
            QSqlQuery updateQuery(db);
            updateQuery.prepare("DELETE FROM refresh_tokens WHERE user_id = :userID");
            updateQuery.bindValue(":userID", userID);
            if (!updateQuery.exec()) {
                qDebug() << "Delete failed:" << updateQuery.lastError().text();
                QString mes = "Failed to update RefreshToken!";
                return QHttpServerResponse(mes, QHttpServerResponse::StatusCode::InternalServerError);
            }

            if (!Token.addTKBlacklist(jti, exp)) {
                QString mes = "Failed to revoked Token!";
                return QHttpServerResponse(mes, QHttpServerResponse::StatusCode::InternalServerError);
            }
            QString mes = "Logout is successful!";
            return QHttpServerResponse(mes, QHttpServerResponse::StatusCode::Ok);
        } else {
            QString mes = "RefreshToken does not exist for the user!";
            return QHttpServerResponse(mes, QHttpServerResponse::StatusCode::BadRequest);
        }
    }

    // Xử lý các token hết hạn bằng refreshtoken
    QHttpServerResponse handlerfToken (const QHttpServerRequest &request)
    {
        QJsonWebToken JTrftoken = Token.getRFtk(request);

        QString rfToken = JTrftoken.getToken();
        QString payload = JTrftoken.getPayloadQStr();

        bool validateTK = JTrftoken.isValid();
        if (!validateTK)
        {   QString mes = "Refresh token is not validate!";
            return QHttpServerResponse(mes,QHttpServerResponse::StatusCode::Unauthorized);
        }
        if (!Token.TimelifeTK(payload))
        {
            QString mes = " Refresh token is expired";
            return QHttpServerResponse(mes,QHttpServerResponse::StatusCode::Unauthorized);
        }
        QSqlQuery query(db);
        query.prepare("SELECT user_id FROM refresh_tokens WHERE token = :token");
        query.bindValue(":token", rfToken);
        if (!query.exec()) {
            qDebug() << "Lỗi khi truy vấn cơ sở dữ liệu:" << query.lastError().text();
            return QHttpServerResponse(QHttpServerResponse::StatusCode::InternalServerError);
        }

        if (!query.next()) {
            QString mes = "Refresh token không tồn tại";
            return QHttpServerResponse(mes, QHttpServerResponse::StatusCode::Unauthorized);
        }
        QString userId = query.value(0).toString();
        QString newACtk = Token.createAccessToken(userId);

        QJsonObject jsonResponse;
        jsonResponse["access_token:"] = newACtk;
        QJsonDocument jsonDoc(jsonResponse);
        QByteArray responseBody = jsonDoc.toJson();
        return QHttpServerResponse("application/json",responseBody,QHttpServerResponse::StatusCode::Ok);
    };


private:
    QSqlDatabase db;
    TokenManager Token;

    bool authenticateUser(const QString &username, const QString &password) {
        qDebug() << "Authenticating user:" << username;
        QString hashpass =  hashPassword(password);
        qDebug() << "Hashed password:" << hashpass;

        QSqlQuery query(db);
        query.prepare("SELECT * FROM users WHERE name = :username AND password = :password");
        query.bindValue(":username", username);
        query.bindValue(":password", hashpass);

        if (!query.exec()) {
            qDebug() << "Query failed:" << query.lastError().text();
            return false;
        }
        bool isAuthenticated = query.next();
        qDebug() << "Authentication result:" << isAuthenticated;
        return isAuthenticated;
    }


    bool addNewUser(const QString &username, const QString &email, const QString &hashedPassword) {
        QSqlQuery insertQuery(db);
        insertQuery.prepare("INSERT INTO users (name, email, password,Admin) VALUES (:name, :email,:password,:Admin)");
        insertQuery.bindValue(":name", username);
        insertQuery.bindValue(":email", email);
        insertQuery.bindValue(":password", hashedPassword);
        insertQuery.bindValue(":Admin", 0);

            if (insertQuery.exec()) {
                return true;
            } else {
                qDebug() << "Database error:" << insertQuery.lastError().text();
                return false;
            }
        }


    QString getUserIdByUsername(const QString &username) {
        QSqlQuery query(db);
        query.prepare("SELECT id FROM users WHERE name = :username");
        query.bindValue(":username", username);
        if (!query.exec()) {
            qDebug() << "Không thể lấy user_id cho người dùng:" << query.lastError().text();
            return QString();
        }

        if (query.next()) {
            return query.value(0).toString();
        }

        return QString();
    }

    QString hashPassword(const QString &password) {
        QByteArray passwordBytes = password.toUtf8();
        QByteArray hashedBytes = QCryptographicHash::hash(passwordBytes, QCryptographicHash::Sha256);
        return QString(hashedBytes.toHex());
    }
    bool hasContentType(const QHttpServerRequest &request) {
        auto headers = request.headers();
        for (const auto &header : headers) {
            if (header.first == "Content-Type" && header.second == "application/x-www-form-urlencoded") {
                return true;
            }
        }
        return false;
    }

};

#endif // USER_H
