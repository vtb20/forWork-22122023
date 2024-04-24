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
    // QHttpServerResponse Register(const QHttpServerRequest &request) {
    //     QJsonDocument jsonDoc = QJsonDocument::fromJson(request.body());
    //     QJsonObject jsonObj = jsonDoc.object();

    //     QString username = jsonObj.value("username").toString();
    //     QString email = jsonObj.value("email").toString();
    //     QString password = jsonObj.value("password").toString();

    //     if (password.length() < 6 || password.length() > 20) {
    //         return QHttpServerResponse("Invalid password length",QHttpServerResponse::StatusCode::BadRequest);
    //     }
    //     QString hashedPassword = hashPassword(password);
    //     if (username.length() < 6 || username.length() > 15 )
    //     {
    //         return QHttpServerResponse("Invalid username length",QHttpServerResponse::StatusCode::BadRequest);
    //     }
    //     if (email.length()< 10)
    //     {
    //         return QHttpServerResponse("Invalid email length",QHttpServerResponse::StatusCode::BadRequest);
    //     }
    //     if (addNewUser(username, email, hashedPassword)) {
    //         return QHttpServerResponse("Registration successful",QHttpServerResponse::StatusCode::Ok);
    //     } else {
    //         return QHttpServerResponse("Failed to register user",QHttpServerResponse::StatusCode::BadRequest);
    //     }
    // };

    //Hàm Xử lý login request
   QHttpServerResponse Login_for_O2(const QHttpServerRequest &request) {
        QByteArray data = request.body();

        QString username;
        QString password;

        // kiểm tra sự tồn tại của trường content-type và giá trị cúa nó có đúng là urlencode không ?
        if (hasContentType(request)==false)
        {
            return ErrorResponse("invalid request!","Missing requied or wrong parameter!");
        }
        // chuyển data từ bytear sang string dùng urlquery để lấy thông tin cần thiết
        QUrlQuery urlQuery(QString::fromUtf8(data));

         // truy xuất dữ liệu dưới từ body thông tin username và password ra
        username = urlQuery.queryItemValue("username");
        password = urlQuery.queryItemValue("password");
        //Kiểm tra xem các trường này có hay không
        if(username.isEmpty()||password.isEmpty())
            {
                return ErrorResponse("invalid_request","Missing username or password");
            }
            // Tiếp túc sủ dụng username và password từ client để xác thực với database

        bool isAuthenticated = authenticateUser(username, password);
        if (isAuthenticated) {
                QString userID = getUserIdByUsername(username);
                qDebug()<<"Authentication from user:"<<userID;
                return ResponseWithTokens(userID);

        } else {
                return ErrorResponse("invalid_request","Wrong username or password");
        }
    }

    // Hàm login cho auth 1.0
    QHttpServerResponse Login_for_O1(const QHttpServerRequest &request) {
        QByteArray data = request.body();

        QString username;
        QString password;
        // kiểm tra sự tồn tại của trường content-type và giá trị cúa nó có đúng là urlencode không ?
        if (hasContentType(request)==false)
        {
            return ErrorResponse("invalid request!","Missing requied or wrong parameter!");
        }
        // chuyển data từ bytear sang string dùng urlquery để lấy thông tin cần thiết
        QUrlQuery urlQuery(QString::fromUtf8(data));

        // truy xuất dữ liệu dưới từ body thông tin username và password ra
        username = urlQuery.queryItemValue("username");
        password = urlQuery.queryItemValue("password");
        //Kiểm tra xem các trường này có hay không
        if(username.isEmpty()||password.isEmpty())
        {
            return ErrorResponse("invalid_request","Missing username or password");
        }
        // Tiếp túc sủ dụng username và password từ client để xác thực với database
        bool isAuthenticated = authenticateUser(username, password);
        if (isAuthenticated) {

                QString userID = getUserIdByUsername(username);
                qDebug()<<"Authentication from user:"<<userID;
                return ResponseWithOauth1Tokens(userID);

        } else {
            return ErrorResponse("invalid_request","Wrong username or password");
        }
    }
    
    //Hàm xử lý refresh token cho o2
    QHttpServerResponse handleRereshToken(const QHttpServerRequest &request){

        QByteArray data = request.body();
            QUrlQuery urlQuery(QString::fromUtf8(data));

            // Xử lý refresh token
            QString refresh_token = urlQuery.queryItemValue("refresh_token");
            if (refresh_token.isEmpty())
            {
                return ErrorResponse("invalid_request", "Missing refreshtoken in your requset");
            }
            QStringList listJwtParts = refresh_token.split(".");
            if (listJwtParts.count() != 3)
            {
                return ErrorResponse("invalid_request", "token must have the format xxxx.yyyyy.zzzzz");
            }
            QJsonWebToken JTrftoken = Token.getRFtk(refresh_token);
            QString OldrfToken = JTrftoken.getToken();
            qDebug()<<"refresh token try to get new acTk from client:"<<OldrfToken;
            //Kiểm tra refresh token với secret key

            bool validateTK = JTrftoken.isValid();
            if (!validateTK)
            {
                return ErrorResponse("invalid_request", " Refresh token is wrong");
            }

            // Lấy giá trị của khóa "sub" = userID
            QString userID = JTrftoken.claim("sub");
            QString expime = JTrftoken.claim("exp");
            QString rfTokenID = JTrftoken.claim("jti");

            //Kiểm tra thời gian sống của refresh token
            if (!Token.TimelifeTK(expime))
            {
                return ErrorResponse("invalid_request", " Refresh token is expired");
            }
            if(!checkInvalidate(rfTokenID,refresh_token,userID))
            {
                return ErrorResponse("invalid_request", " Your token does not exist");
            }
            // khởi tạo token mới cho client
            QString newACtk = Token.createAccessToken(userID,"2.0");
            qDebug()<<"New access token create for users:"<<newACtk;
            if (!remove_refreshtoken_Oauth2(userID,rfTokenID)){
                qDebug()<<"refresh-token cant remove!";
                }
            else{
                qDebug()<<"Removed token successful before create new token!";

            }
            QString newRefreshTK = Token.createRFtoken(userID,expime);

            QJsonObject jsonResponse;
            jsonResponse["access_token"] = newACtk;
            jsonResponse["refresh_token"]= newRefreshTK;
            jsonResponse["token_type"] = "Bearer";
            jsonResponse["expires_in"] = 7200;// 2 tiếng đồng hồ
            QJsonDocument jsonDoc(jsonResponse);
            QByteArray responseBody = jsonDoc.toJson();
            return QHttpServerResponse("application/json",responseBody,QHttpServerResponse::StatusCode::Ok);

    };

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
