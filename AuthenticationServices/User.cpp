

#include "user.h"
#include "qsqlrecord.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QSqlQuery>
#include <QCryptographicHash>
#include <QDebug>
#include <QUrlQuery>

User::User() : db(DatabaseConnection::connect()) {}

 // OAuth 2.0
    QHttpServerResponse User::Login_for_O2(const QHttpServerRequest &request) {
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
    QHttpServerResponse User::Login_for_O1(const QHttpServerRequest &request) {
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
    QHttpServerResponse User::handleRereshToken(const QHttpServerRequest &request){

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

    //Xử lý thu hồi refresh token hay logout o2
    QHttpServerResponse User::Logout_o2(const QHttpServerRequest &request) {

        QByteArray requestData = request.body(); // Dữ liệu được gửi trong phần thân của yêu cầu HTTP

        QJsonDocument jsonDoc = QJsonDocument::fromJson(requestData);
        QJsonObject jsonObject = jsonDoc.object();

        // Trích xuất giá trị rftoken từ JSON
        QString token = jsonObject["token"].toString();

        QJsonWebToken refresh_tk = Token.getRFtk(token);
        QString payload = refresh_tk.getPayloadQStr();
        QJsonDocument payloadJs = QJsonDocument::fromJson(payload.toUtf8());
        QJsonObject PayLoadJSObject = payloadJs.object();

        // Lấy giá trị của khóa "sub" = userID
        QString userID = PayLoadJSObject["sub"].toString();

        // Kiểm tra sự tồn tại của các thông tin yêu cầu
        if (token.isEmpty()) {
            QString mes = "Missing token in request!";
            return QHttpServerResponse(mes, QHttpServerResponse::StatusCode::BadRequest);
        }
        // Xoá refresh token ra của user tương ứng ra khỏi database
        if (!remove_refreshtoken_Oauth2(userID,token)) {
            QString mes = "Failed to revoke RefreshToken!";
            return QHttpServerResponse(mes, QHttpServerResponse::StatusCode::InternalServerError);
        }
        QString mes = "Logout is successful!";
        return QHttpServerResponse(mes, QHttpServerResponse::StatusCode::Ok);
    }

    //Logout cho o1
    QHttpServerResponse User::Logout_o1(const QHttpServerRequest &request) {

        QList<std::pair<QByteArray, QByteArray>> headers = request.headers();
        QString accessToken_o1 = Token.extractToken_o1(headers);

        // Kiểm tra sự tồn tại của các thông tin yêu cầu
        if (accessToken_o1.isEmpty()) {
            QString mes = "Missing token in request!";
            return QHttpServerResponse(mes, QHttpServerResponse::StatusCode::BadRequest);
        }
        QJsonWebToken actoken = Token.getAccesToken_01(accessToken_o1);
        QString exp = actoken.claim("exp");
        QString IDtoken = actoken.claim("iat");

        if(!Token.addTKBlacklist(IDtoken,exp))
        {
            QString mes = "Failed to add Access token to blacklist!";
            return QHttpServerResponse(mes, QHttpServerResponse::StatusCode::InternalServerError);
        }
        QString mes = "Logout is successful!";
        return QHttpServerResponse(mes, QHttpServerResponse::StatusCode::Ok);

    }

    // Test reponsive data to user
    QHttpServerResponse User::Example(const QHttpServerRequest &request) {

        QList<std::pair<QByteArray, QByteArray>> headers = request.headers();
        QString typeToken = Token.checkingTypeTOKEN(headers);
        if (typeToken == "OAuth")
        {
            QString accessToken = Token.extractToken_o1(headers);

            QJsonWebToken actoken = Token.getAccesToken_01(accessToken);
            QString payload = actoken.getPayloadQStr();
            QJsonDocument payloadJs = QJsonDocument::fromJson(payload.toUtf8());
            QJsonObject PayLoadJSObject = payloadJs.object();

            // Lấy giá trị của khóa "sub" = userID
            QString userID = PayLoadJSObject["sub"].toString();

            QSqlQuery query(db);
            query.prepare("SELECT * FROM users WHERE id = :user_id");
            query.bindValue(":user_id", userID);

            if (!query.exec()) {
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
            qDebug()<<"thông tin được trả về cho user:"<<jsonData;
            return QHttpServerResponse("application/json", jsonData, QHttpServerResponse::StatusCode::Ok);
        }

        if (typeToken == "Bearer")
        {
            QString accessToken = Token.extractToken_o2(headers);

            QJsonWebToken actoken = Token.getAccesToken_o2(accessToken);
            QString payload = actoken.getPayloadQStr();
            QJsonDocument payloadJs = QJsonDocument::fromJson(payload.toUtf8());
            QJsonObject PayLoadJSObject = payloadJs.object();

            // Lấy giá trị của khóa "sub" = userID
            QString userID = PayLoadJSObject["sub"].toString();

            QSqlQuery query(db);
            query.prepare("SELECT * FROM users WHERE id = :user_id");
            query.bindValue(":user_id", userID);

            if (!query.exec()) {
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
            qDebug()<<"thông tin được trả về cho user:"<<jsonData;
            return QHttpServerResponse("application/json", jsonData, QHttpServerResponse::StatusCode::Ok);
        }
        return QHttpServerResponse(QHttpServerResponse::StatusCode::InternalServerError);
    }


    // Xác thực thong tin đăng nhập user
    bool User::authenticateUser(const QString &username, const QString &password) {
        QString hashpass =  hashPassword(password);

        QSqlQuery query(db);
        query.prepare("SELECT * FROM users WHERE name = :username AND password = :password");
        query.bindValue(":username", username);
        query.bindValue(":password", hashpass);

        if (!query.exec()) {
            qDebug() << "Query failed:" << query.lastError().text();
            return false;
        }
        bool isAuthenticated = query.next();
        qDebug() << "Xác thực thành công ?:" << isAuthenticated;
        return isAuthenticated;
    }


    // bool addNewUser(const QString &username, const QString &email, const QString &hashedPassword) {
    //     QSqlQuery insertQuery(db);
    //     insertQuery.prepare("INSERT INTO users (name, email, password,Admin) VALUES (:name, :email,:password,:Admin)");
    //     insertQuery.bindValue(":name", username);
    //     insertQuery.bindValue(":email", email);
    //     insertQuery.bindValue(":password", hashedPassword);
    //     insertQuery.bindValue(":Admin", 0);

    //         if (insertQuery.exec()) {
    //             return true;
    //         } else {
    //             qDebug() << "Database error:" << insertQuery.lastError().text();
    //             return false;
    //         }
    //     }

    //Lấy UserID từ username
    QString User::getUserIdByUsername(const QString &username) {
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
    // mã hóa password trước khi xác thực
    QString User::hashPassword(const QString &password) {
        QByteArray passwordBytes = password.toUtf8();
        QByteArray hashedBytes = QCryptographicHash::hash(passwordBytes, QCryptographicHash::Sha256);
        return QString(hashedBytes.toHex());
    }

    //Hàm Kiểm tra giá trị content
    bool User::hasContentType(const QHttpServerRequest &request) {
        auto headers = request.headers();
        for (const auto &header : headers) {
            if (header.first == "Content-Type" && header.second == "application/x-www-form-urlencoded") {
                return true;
            }
        }
        return false;
    }

    //Hàm phản hồi kèm access token + refresh token cho oAuth 2.0
    QHttpServerResponse User::ResponseWithTokens(const QString &userID) {
        QString token = Token.createAccessToken(userID,"2.0");
        QString rfToken = Token.createRFtoken(userID);

        QJsonObject jsonResponse;
        jsonResponse["access_token"] = token;
        jsonResponse["refresh_token"] = rfToken;
        jsonResponse["token_type"] = "Bearer";
        jsonResponse["expires_in"] = 7200;// 2 tiếng đồng hồ

        QJsonDocument jsonResponseDoc(jsonResponse);
        QByteArray responseBody = jsonResponseDoc.toJson();
        qDebug()<<"Responsive authentication to User:"<<responseBody;
        return QHttpServerResponse("application/json", responseBody, QHttpServerResponse::StatusCode::Ok);
    }
    //Hàm phản hồi kèm oauth
    QHttpServerResponse User::ResponseWithOauth1Tokens(const QString &userID) {
        QString tokens = Token.createAccessToken(userID,"1.0");

        qDebug()<<"oauth_token:"<<tokens;

        QUrlQuery query;
        query.addQueryItem("oauth_token", tokens);
        QByteArray responseBody = query.toString(QUrl::FullyEncoded).toUtf8();
        qDebug()<<"Responsive authentication to User:"<<responseBody;

        return QHttpServerResponse("application/x-www-form-urlencoded", responseBody, QHttpServerResponse::StatusCode::Ok);
    }
    // Hàm khởi tạo thông báo lỗi
    QHttpServerResponse User::ErrorResponse(const QString &errorMessage,const QString &errorDetail) {
        QJsonObject jsonResponse;
        jsonResponse["error"] = errorMessage;
        jsonResponse["error_description"] = errorDetail;

        QJsonDocument jsonResponseDoc(jsonResponse);
        QByteArray responseBody = jsonResponseDoc.toJson();
        return QHttpServerResponse("application/json", responseBody, QHttpServerResponse::StatusCode::Unauthorized);
    }
    //Hàm kiểm tra sự tồn tại của refreshtoken
    bool User::checkInvalidate(const QString &token_id, const QString &token,const QString &userID)
    {
        QSqlQuery checkqr(db);
        checkqr.prepare("SELECT * FROM refresh_tokens WHERE id = :token_id AND token = :token_value and user_id = :user_id");
        checkqr.bindValue(":token_id", token_id);
        checkqr.bindValue(":token_value", token);
        checkqr.bindValue(":user_id", userID);

        if (!checkqr.exec()) {
            qDebug() << "Query failed:" << checkqr.lastError().text();
            return false;
        }

        if(checkqr.next())
        {
            qDebug() << "An id that matches the token value exists";
            return true;
        }
        else{
            qDebug() << "no id matching token value exists.";
            return false;
        }
    }

    // xóa refresh token ra khỏi database
    bool User::remove_refreshtoken_Oauth2(const QString &UserId, const QString &token_id){
        QSqlQuery updateQuery(db);
        updateQuery.prepare("DELETE FROM refresh_tokens WHERE user_id = :userID and id = :token_id");
        updateQuery.bindValue(":userID", UserId);
        updateQuery.bindValue(":token_id", token_id);

        if (!updateQuery.exec()) {
            qDebug() << "Delete failed:" << updateQuery.lastError().text();
            return false;
        }
        int affectedRows = updateQuery.numRowsAffected();
        if (affectedRows > 0) {
            qDebug() << "Refresh token của user đã được xóa thành công cho user ID: " << UserId;
            return true;
        } else {
            qDebug() << "refresh token đã được xóa trước đó cho user ID: " << UserId;
            return true;
        }
    }



