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

class TokenManager:public QObject {
    Q_OBJECT

public:
    TokenManager():db(DatabaseConnection::connect()){
        // Khởi tạo timer và thiết lập khoảng thời gian định kỳ
        cleanupBLTimer = new QTimer(this);
        cleanupBLTimer->setInterval(5 * 60 * 60 * 1000); // 5 tiếng
        // Kết nối signal và slot
        connect(cleanupBLTimer, &QTimer::timeout, this, &TokenManager::removeExpiredTokensFromBlacklist);
        cleanupBLTimer->start();
    }

    //Hàm tạo accessToken
    QString createAccessToken(const QString &userID,const QString &version) {
        QJsonWebToken jwt;
        QString ID = generateTokenId(userID);

        QJsonObject header;
        header["alg"] = "HS256";
        header["typ"] = "JWT";
        QJsonDocument headerDoc(header);
        jwt.setHeaderJDoc(headerDoc);

        jwt.appendClaim("sub", userID);
        jwt.appendClaim("jti", ID);
        jwt.appendClaim("iat", QString::number(QDateTime::currentDateTime().toSecsSinceEpoch()));
        if(version ==  "2.0"){
            jwt.appendClaim("exp", QString::number(QDateTime::currentDateTime().addSecs(2 * 60 * 60).toSecsSinceEpoch()));
            jwt.appendClaim("version",version);
            QSettings settings("C:/Users/vuthe/Desktop/RestFullAPI/untitled/secretkey.env", QSettings::IniFormat);
            QString secretKey = settings.value("SECRET_KEY").toString();
            jwt.setSecret(secretKey);
        }
        if(version == "1.0")
        {   jwt.appendClaim("version",version);
            jwt.appendClaim("exp", QString::number(QDateTime::currentDateTime().addDays(1).toSecsSinceEpoch()));
            QSettings settings("C:/Users/vuthe/Desktop/RestFullAPI/untitled/secretkey.env", QSettings::IniFormat);
            QString secretKey = settings.value("SECRET_KEY_O1").toString();
            jwt.setSecret(secretKey);
       }
       QString token = jwt.getToken();

        return token;
    }

        //Hàm tạo refresh token
    QString createRFtoken(const QString &userID, const QString &exp = "") {
        QString rfTokenId = generateTokenId(userID);
        QString expirationTime;
        if (exp.isEmpty()) {
            expirationTime = QString::number(QDateTime::currentDateTime().addDays(1).toSecsSinceEpoch());
        } else {
            expirationTime = exp;
        }
        QString iatTime = QString::number(QDateTime::currentDateTime().toSecsSinceEpoch());
        QJsonWebToken rfToken;
        rfToken.appendClaim("sub", userID);
        rfToken.appendClaim("jti", rfTokenId);
        rfToken.appendClaim("iat", iatTime);
        rfToken.appendClaim("exp",expirationTime);

        QJsonObject rfTokenHeader;
        rfTokenHeader["alg"] = "HS256";
        rfTokenHeader["typ"] = "JWT";
        QJsonDocument rfTokenHeaderDoc(rfTokenHeader);
        rfToken.setHeaderJDoc(rfTokenHeaderDoc);

        QString rfSecretKey = getSecretKeyrftk();
        rfToken.setSecret(rfSecretKey);
        QString rfTokenString = rfToken.getToken();
        //Thêm refresh token mới vào trong bảng
        QSqlQuery insertQuery(db);
        insertQuery.prepare("INSERT INTO refresh_tokens (id,user_id, token, expires_at, iat) VALUES (:rfId, :user_id, :token, :expires_at, :iat)");
        insertQuery.bindValue(":rfId", rfTokenId);
        insertQuery.bindValue(":user_id", userID);
        insertQuery.bindValue(":token", rfTokenString);
        insertQuery.bindValue(":expires_at", expirationTime);
        insertQuery.bindValue(":iat", iatTime);

        if (!insertQuery.exec()) {
            qDebug() << "Insert failed:" << insertQuery.lastError().text();
            return QString();
        }
        return rfTokenString;
    }

    //Hàm khởi tạo ID cho refersh TK
    QString generateTokenId(const QString &userID) {
        QString uniqueString = QDateTime::currentDateTimeUtc().toString(Qt::ISODate) + userID;
        QByteArray hashBytes = QCryptographicHash::hash(uniqueString.toUtf8(), QCryptographicHash::Md5);
        return QString::fromLatin1(hashBytes.toHex());
    }
    // Xóa AC token hết hạn khỏi database
    void removeExpiredTokensFromBlacklist() {
        QSqlQuery query(db);
        query.prepare("DELETE FROM jwt_blacklist WHERE expires_at < :current_time");
        query.bindValue(":current_time", QString::number(QDateTime::currentDateTime().toSecsSinceEpoch()));

        if (!query.exec()) {
            qDebug() << "Không thể xóa các access token hết hạn từ blacklist:" << query.lastError().text();
        } else {
            qDebug() << "Xóa các access token hết hạn từ blacklist thành công.";
        }
    }
    //Hàm Kiểm Tra thời gian sống của Token
    bool TimelifeTK(const QString &tl) {
        QJsonDocument jsonDoc = QJsonDocument::fromJson(tl.toUtf8());
        QJsonObject jsonObj = jsonDoc.object();
        QString expValue = jsonObj.value("exp").toString();

        qint64 expTimestamp = expValue.toLongLong();
        QDateTime currentDateTime = QDateTime::currentDateTimeUtc();
        QDateTime expDateTime = QDateTime::fromSecsSinceEpoch(expTimestamp, Qt::UTC);
        if (currentDateTime > expDateTime) {
            return false; // Token đã hết hạn
        } else {
            return true; // Token vẫn còn hợp lệ
        }
    }

    //Hàm lấy Refresh Token từ request
    QJsonWebToken getRFtk(const QHttpServerRequest &request)
    {
        QString tokenJsonString = request.body();
        QJsonDocument jsonDocument = QJsonDocument::fromJson(tokenJsonString.toUtf8());
        QJsonObject jsonObject = jsonDocument.object();
        QString rfToken = jsonObject.value("refresh_token").toString();
        QSettings settings("C:/Users/vuthe/Desktop/RestFullAPI/untitled/secretkey.env", QSettings::IniFormat);
        QString rfSecretKey = settings.value("REFRESH_SECRET_KEY").toString();
        QJsonWebToken rftoken = QJsonWebToken::fromTokenAndSecret(rfToken, rfSecretKey);
        return rftoken;
    }
    //Hàm lấy access token từ request
    QJsonWebToken getAccesToken(const QHttpServerRequest &request){
        QList<std::pair<QByteArray, QByteArray>> headers = request.headers();

        QString accessToken = extractToken(headers);

        QSettings settings("C:/Users/vuthe/Desktop/RestFullAPI/untitled/secretkey.env", QSettings::IniFormat);
        QString secretKey = settings.value("SECRET_KEY").toString();
        QJsonWebToken token = QJsonWebToken::fromTokenAndSecret(accessToken, secretKey);
        return token;
    }
    // Loại bỏ tiền tố trong header request Authorizarion
    QByteArray extractToken(const QList<std::pair<QByteArray, QByteArray>>& headers) {
        for (const auto& header : headers) {
            if (header.first == "Authorization") {
                // Loại bỏ phần "Bearer " để lấy chỉ token
                return header.second.mid(7); // "Bearer " có độ dài là 7 ký tự
            }
        }
        return ""; // Trả về QString rỗng nếu không tìm thấy
    }

    QString getSecretKeyrftk(){
        QSettings settings("C:/Users/vuthe/Desktop/RestFullAPI/untitled/secretkey.env", QSettings::IniFormat);
        QString rfSecretKey = settings.value("REFRESH_SECRET_KEY").toString();
        return rfSecretKey;
    }

    QString getIDtoken(const QString &Payload) {
        QString jti = "";
        QJsonDocument jsonDoc = QJsonDocument::fromJson(Payload.toUtf8());

        if (!jsonDoc.isNull() && jsonDoc.isObject()) {
            QJsonObject payloadObj = jsonDoc.object();
            // Kiểm tra sự tồn tại của khóa "jti" và lấy giá trị nếu có
            if (payloadObj.contains("jti")) {
                jti = payloadObj.value("jti").toString();
            }
        }
        return jti;
    }

    // Hàm thêm token vào blacklist
    bool addTKBlacklist(const QString &idToken, QString &expTime)
    {
        QSqlQuery insertQuery(db);
        insertQuery.prepare("INSERT INTO jwt_blacklist (jti,expires_at) VALUES (:jti, :expires_at)");
        insertQuery.bindValue(":jti", idToken);
        insertQuery.bindValue(":expires_at", expTime);
        if (insertQuery.exec()) {
            return true;
        } else {
            qDebug() << "Database error:" << insertQuery.lastError().text();
            return false;
        }
    }
    //Hàm kiểm tra token có trong Blacklist không?
    bool TokenInBlacklit(const QString &IDtoken) {
        QSqlQuery query(db);
        query.prepare("SELECT * FROM jwt_blacklist WHERE jti = :IDtoken");
        query.bindValue(":IDtoken", IDtoken);

        if (!query.exec()) {
            qDebug() << "Database error:" << query.lastError().text();
            return false; // Trả về false nếu có lỗi khi thực thi truy vấn
        }

        return query.next(); // Trả về true nếu tìm thấy IDtoken trong bảng jwt_blacklist, ngược lại trả về false
    }
    bool removeOldToken(){
          QSqlQuery deletequery(db);
          deletequery.prepare("DELETE FROM jwt_blacklist WHERE expires_at < :current_time");
    };
private:
    QSqlDatabase db;
    QTimer *cleanupBLTimer;;

};
#endif // TOKENMANAGER_H
