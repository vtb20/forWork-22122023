
#include "TokenManager.h"
#include "DatabaseConnection.h"



TokenManager::TokenManager():db(DatabaseConnection::connect()){
        // Khởi tạo timer và thiết lập khoảng thời gian định kỳ
        cleanupBLTimer = new QTimer(this);
        cleanupBLTimer->setInterval(30*  60 * 1000); // 30 phút
        // Kết nối signal và slot
        connect(cleanupBLTimer, &QTimer::timeout, this, &TokenManager::removeExpiredTokens);
        cleanupBLTimer->start();
    }

    //Hàm tạo accessToken
    QString TokenManager::createAccessToken(const QString &userID,const QString &version) {
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
    QString TokenManager::createRFtoken(const QString &userID, const QString &exp) {
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
    QString TokenManager::generateTokenId(const QString &userID) {
        QString uniqueString = QDateTime::currentDateTimeUtc().toString(Qt::ISODate) + userID;
        QByteArray hashBytes = QCryptographicHash::hash(uniqueString.toUtf8(), QCryptographicHash::Md5);
        return QString::fromLatin1(hashBytes.toHex());
    }

    // Xóa refresh token hết hạn khỏi database
    void TokenManager::removeExpiredTokens() {
        QSqlQuery query(db);
        query.prepare("DELETE FROM refresh_tokens WHERE expires_at < UNIX_TIMESTAMP(NOW())");
        query.bindValue(":current_time", QString::number(QDateTime::currentDateTime().toSecsSinceEpoch()));

        if (!query.exec()) {
            qDebug() << "Không thể xóa các refresh token hết hạn :" << query.lastError().text();
        } else {
            qDebug() << "Xóa các refresh token hết hạn thành công.";
        }
    }
    //Hàm Kiểm Tra thời gian sống của Token
    bool TokenManager::TimelifeTK(const QString &expValue) {
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
    QJsonWebToken TokenManager::getRFtk(const QString &Refreshtokn)
    {
        QString tokenString = Refreshtokn;
        QSettings settings("C:/Users/vuthe/Desktop/RestFullAPI/untitled/secretkey.env", QSettings::IniFormat);
        QString rfSecretKey = settings.value("REFRESH_SECRET_KEY").toString();
        QJsonWebToken rftoken = QJsonWebToken::fromTokenAndSecret(tokenString, rfSecretKey);
        return rftoken;
    }
    //Hàm lấy access token từ request
    QJsonWebToken TokenManager::getAccesToken_o2(const QString &accessToken){

        QSettings settings("C:/Users/vuthe/Desktop/RestFullAPI/untitled/secretkey.env", QSettings::IniFormat);
        QString secretKey = settings.value("SECRET_KEY").toString();
        QJsonWebToken token = QJsonWebToken::fromTokenAndSecret(accessToken, secretKey);
        return token;
    }
    QJsonWebToken TokenManager::getAccesToken_01(const QString &accessToken){
        QSettings settings("C:/Users/vuthe/Desktop/RestFullAPI/untitled/secretkey.env", QSettings::IniFormat);
        QString secretKey = settings.value("SECRET_KEY_O1").toString();
        QJsonWebToken token = QJsonWebToken::fromTokenAndSecret(accessToken, secretKey);
        return token;
    }
    // Loại bỏ tiền tố trong header request Authorizarion
    QByteArray TokenManager::extractToken_o2(const QList<std::pair<QByteArray, QByteArray>>& headers) {
        for (const auto& header : headers) {
            if (header.first == "Authorization") {
                // Loại bỏ phần "Bearer " để lấy chỉ token
                return header.second.mid(7); // "Bearer " có độ dài là 7 ký tự

            }
        }
        return ""; // Trả về QString rỗng nếu không tìm thấy
    }

    QByteArray TokenManager::extractToken_o1(const QList<std::pair<QByteArray, QByteArray>>& headers) {
        for (const auto& header : headers) {
            if (header.first == "Authorization") {
                // Loại bỏ phần "OAuth oauth_token=" để lấy chỉ token
                QByteArray authValue = header.second;
                int startIndex = authValue.indexOf("oauth_token=\"");
                if (startIndex != -1) {
                    return authValue.mid(startIndex + 13, authValue.length() - startIndex - 14);
                }
            }
        }
        return ""; // Trả về QString rỗng nếu không tìm thấy
    }


    QString TokenManager::getSecretKeyrftk(){
        QSettings settings("C:/Users/vuthe/Desktop/RestFullAPI/untitled/secretkey.env", QSettings::IniFormat);
        QString rfSecretKey = settings.value("REFRESH_SECRET_KEY").toString();
        return rfSecretKey;
    }


    // Hàm thêm token vào blacklist
    bool TokenManager::addTKBlacklist(const QString &idToken, QString &expTime)
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
    bool TokenManager::TokenInBlacklit(const QString &IDtoken) {
        QSqlQuery query(db);
        query.prepare("SELECT * FROM jwt_blacklist WHERE jti = :IDtoken");
        query.bindValue(":IDtoken", IDtoken);

        if (!query.exec()) {
            qDebug() << "Database error:" << query.lastError().text();
            return false; // Trả về false nếu có lỗi khi thực thi truy vấn
        }

        if (query.next()) // Trả về true nếu tìm thấy IDtoken trong bảng jwt_blacklist, ngược lại trả về false
            return true;
        else
            return false;
    }


    QString TokenManager::checkingTypeTOKEN(const QList<std::pair<QByteArray, QByteArray>>& headers)
    {
        for (const auto& header : headers) {
            if (header.first == "Authorization" && header.second.startsWith("OAuth")) {
                // Loại bỏ phần "OAuth " để lấy chỉ token
                return "OAuth";
            }
            if (header.first == "Authorization" && header.second.startsWith("Bearer")) {
                // Loại bỏ phần "Bearer " để lấy chỉ token
                return "Bearer";
            }
        }
        return "";
    }



