#include "AuthenticationManager.h"
#include "qsqlrecord.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QSqlQuery>
#include <QCryptographicHash>
#include <QDebug>
#include <QUrlQuery>

AuthenticationManager::AuthenticationManager() : db(DatabaseConnection::connect()) {}

 // OAuth 2.0

    QHttpServerResponse AuthenticationManager::Login_for_O2(const QHttpServerRequest &request) {
        QByteArray data = request.body();

        QString username;
        QString password;

        // kiểm tra sự tồn tại của trường content-type và giá trị cúa nó có đúng là urlencode không ?
        if (hasContentTypeURLencode(request)==false)
        {
            return BadRequestResponse("invalid request!","Missing requied or wrong parameter!");
        }
        // chuyển data từ bytear sang string dùng urlquery để lấy thông tin cần thiết
        QUrlQuery urlQuery(QString::fromUtf8(data));

        // truy xuất dữ liệu dưới từ body thông tin username và password ra
        username = urlQuery.queryItemValue("username");
        password = urlQuery.queryItemValue("password");
        //Kiểm tra xem các trường này có hay không

        if(username.isEmpty()||password.isEmpty())
        {
            return BadRequestResponse("invalid_request","Missing username or password");
        }
        // Tạo đối tượng User và thiết lập username và password
        User user(db);
        user.setUsername(username);
        user.setPassword(password);

        bool isAuthenticated = user.authenticationUser();
        if (isAuthenticated) {
            QString userID = user.getUserIdByUsername();
            qDebug()<<"Authentication from user:"<<userID;
            return ResponseWithTokensO2(userID);

        } else {
            return UnauthorizedResponse("invalid_request","Wrong username or password");
        }
    }

    // Hàm login cho auth 1.0
    QHttpServerResponse AuthenticationManager::Login_for_O1(const QHttpServerRequest &request) {
        QByteArray data = request.body();

        QString username;
        QString password;
        // kiểm tra sự tồn tại của trường content-type và giá trị cúa nó có đúng là urlencode không ?
        if (hasContentTypeURLencode(request)==false)
        {
            return BadRequestResponse("invalid request!","Missing requied or wrong parameter!");
        }
        // chuyển data từ bytear sang string dùng urlquery để lấy thông tin cần thiết
        QUrlQuery urlQuery(QString::fromUtf8(data));

        // truy xuất dữ liệu dưới từ body thông tin username và password ra
        username = urlQuery.queryItemValue("username");
        password = urlQuery.queryItemValue("password");
        //Kiểm tra xem các trường này có hay không
        if(username.isEmpty()||password.isEmpty())
        {
            return BadRequestResponse("invalid_request","Missing username or password");
        }

        User user(db);
        user.setUsername(username);
        user.setPassword(password);

        // Tiếp túc sủ dụng username và password từ client để xác thực với database
        bool isAuthenticated = user.authenticationUser();
        if (isAuthenticated) {

            QString userID = user.getUserIdByUsername();
            qDebug()<<"Authentication from user:"<<userID;
            return ResponseWithOauth1Tokens(userID);

        } else {
            return UnauthorizedResponse("invalid_request","Wrong username or password");
        }
    }

    //Hàm xử lý refresh token cho o2
    QHttpServerResponse AuthenticationManager::handleRereshToken(const QHttpServerRequest &request){

        QByteArray data = request.body();
        QUrlQuery urlQuery(QString::fromUtf8(data));

        // Xử lý refresh token
        QString refresh_token = urlQuery.queryItemValue("refresh_token");
        if (refresh_token.isEmpty())
        {
            return BadRequestResponse("invalid_request", "Missing refreshtoken in your requset");
        }
        QStringList listJwtParts = refresh_token.split(".");
        if (listJwtParts.count() != 3)
        {
            return BadRequestResponse("invalid_request", "token must have the format xxxx.yyyyy.zzzzz");
        }
        QJsonWebToken JTrftoken = Token.getRFtk(refresh_token);
        QString OldrfToken = JTrftoken.getToken();
        qDebug()<<"refresh token try to get new acTk from client:"<<OldrfToken;
        //Kiểm tra refresh token với secret key

        bool validateTK = JTrftoken.isValid();
        if (!validateTK)
        {
            return UnauthorizedResponse("invalid_request", " Refresh token is wrong");
        }

        // Lấy giá trị của khóa "sub" = userID
        QString userID = JTrftoken.claim("sub");
        QString expime = JTrftoken.claim("exp");
        QString rfTokenID = JTrftoken.claim("jti");

        //Kiểm tra thời gian sống của refresh token
        if (!Token.TimelifeTK(expime))
        {
            return UnauthorizedResponse("invalid_request", " Refresh token is expired");
        }
        if(!Token.checkInvalidateRF(rfTokenID,refresh_token,userID))
        {
            return UnauthorizedResponse("invalid_request", " Your token does not exist");
        }
        // khởi tạo token mới cho client
        QString newACtk = Token.createAccessToken(userID,"2.0");
        qDebug()<<"New access token create for users:"<<newACtk;
        if (!Token.remove_refreshtoken_Oauth2(userID,rfTokenID)){
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
    QHttpServerResponse AuthenticationManager::Logout_o2(const QHttpServerRequest &request) {

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
        if (!Token.remove_refreshtoken_Oauth2(userID,token)) {
            QString mes = "Failed to revoke RefreshToken!";
            return QHttpServerResponse(mes, QHttpServerResponse::StatusCode::InternalServerError);
        }
        QString mes = "Logout is successful!";
        return QHttpServerResponse(mes, QHttpServerResponse::StatusCode::Ok);
    }

    //Logout cho o1
    QHttpServerResponse AuthenticationManager::Logout_o1(const QHttpServerRequest &request) {

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
    QHttpServerResponse AuthenticationManager::Example(const QHttpServerRequest &request) {

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
                return BadRequestResponse("Query execution error", query.lastError().text());
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
                return BadRequestResponse("Query execution error", query.lastError().text());
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


    //Hàm phản hồi kèm access token + refresh token cho oAuth 2.0
    QHttpServerResponse AuthenticationManager::ResponseWithTokensO2(const QString &userID) {
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
    QHttpServerResponse AuthenticationManager::ResponseWithOauth1Tokens(const QString &userID) {
        QString tokens = Token.createAccessToken(userID,"1.0");

        qDebug()<<"oauth_token:"<<tokens;

        QUrlQuery query;
        query.addQueryItem("oauth_token", tokens);
        QByteArray responseBody = query.toString(QUrl::FullyEncoded).toUtf8();
        qDebug()<<"Responsive authentication to User:"<<responseBody;

        return QHttpServerResponse("application/x-www-form-urlencoded", responseBody, QHttpServerResponse::StatusCode::Ok);
    }

    // Hàm khởi tạo thông báo lỗi Unauthorized
    QHttpServerResponse AuthenticationManager::UnauthorizedResponse(const QString &errorMessage,const QString &errorDetail) {
        QJsonObject jsonResponse;
        jsonResponse["error"] = errorMessage;
        jsonResponse["error_description"] = errorDetail;

        QJsonDocument jsonResponseDoc(jsonResponse);
        QByteArray responseBody = jsonResponseDoc.toJson();
        return QHttpServerResponse("application/json", responseBody, QHttpServerResponse::StatusCode::Unauthorized);
    }

    // Hàm khởi tạo thông báo lỗi Badrequest
    QHttpServerResponse AuthenticationManager::BadRequestResponse(const QString &errorMessage,const QString &errorDetail) {
        QJsonObject jsonResponse;
        jsonResponse["error"] = errorMessage;
        jsonResponse["error_description"] = errorDetail;

        QJsonDocument jsonResponseDoc(jsonResponse);
        QByteArray responseBody = jsonResponseDoc.toJson();
        return QHttpServerResponse("application/json", responseBody, QHttpServerResponse::StatusCode::BadRequest);
    }

    // Hàm kiểm tra sự tồn tại của trường Content-Type và giá trị của nó
    bool AuthenticationManager::hasContentTypeURLencode(const QHttpServerRequest &request) {
        QList<std::pair<QByteArray, QByteArray>> headers = request.headers();
        for (const auto &header : headers) {
            if (header.first.toLower() == "content-type" && header.second.toLower() == "application/x-www-form-urlencoded") {
                return true;
            }
        }
        return false;
    }
