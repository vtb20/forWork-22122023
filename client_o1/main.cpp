#include <QCoreApplication>
#include <QDateTime>
#include <QFile>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QString>
#include <QTextStream>
#include <QUrlQuery>
#include "setting.h"

OAuthExample::OAuthExample(QObject *parent) : QObject(parent) {
}

 void OAuthExample::login() {
        QUrl url("http://127.0.0.1:8080/o/oauth1/access_token");
        QNetworkRequest request(url);
        request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");

        QByteArray postData;
        QUrlQuery params;
        params.addQueryItem("username", "vtb");
        params.addQueryItem("password", "vtb");
        postData = params.toString(QUrl::FullyEncoded).toUtf8();
        qDebug()<<"Thong tin xac thuc:"<<postData;
        QNetworkReply *reply = manager.post(request, postData);
        connect(reply, &QNetworkReply::finished, this, &OAuthExample::loginReply);
    }

    void OAuthExample::loginReply() {
        QNetworkReply *reply = qobject_cast<QNetworkReply *>(sender());
        qDebug() << "Status code:" << reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (reply->error() == QNetworkReply::NoError) {
            QByteArray response = reply->readAll();
            QString responseSTR = QString::fromUtf8(response);
            qDebug()<<"Thong tin phan hoi xac thuc nguoi dung tu server:"<<responseSTR;
            QString oauthToken = response.split('=')[1];
            if (!oauthToken.isEmpty()) {
                QFile file("C:/Users/vuthe/Desktop/ClientForGetRequest/token10.config");
                if (file.open(QIODevice::WriteOnly)) {
                    QTextStream out(&file);
                    out << "oauth_token: " << oauthToken;
                    file.close();
                    qDebug() << "Tokens đã được lưu vào tệp tokens.config.";
                    getData();
                } else {
                    qDebug() << "Không thể mở tệp tokens.config để ghi.";
                }
            } else {
                qDebug() << "Không tim thay access token trong phan hoi.";
            }
        } else {
            qDebug() << "Error: " << reply->errorString();
        }
        reply->deleteLater();
    }

   void OAuthExample::getData() {
        QFile file("C:/Users/vuthe/Desktop/ClientForGetRequest/token10.config");
        if (!file.open(QIODevice::ReadOnly)) {
            qDebug() << "Không thể mở tệp token10.config";
            return;
        }
        QString configContent = file.readAll();
        file.close();

        QString oauthTokenValue = configContent.split(":")[1].trimmed();
        if (!oauthTokenValue.isEmpty()) {
            qDebug() << "Gia tri của oauth_token:" << oauthTokenValue;
        } else {
            qDebug() << "Không tim thay oauth_token trong file .config";
            return;
        }

        QUrl url("http://127.0.0.1:8080/o/oauth/example");
        QNetworkRequest request(url);

        QString authorizationHeader = QString("OAuth oauth_token=\"%1\"")
                                          .arg(oauthTokenValue);

        request.setRawHeader(QByteArray("Authorization"), authorizationHeader.toUtf8());

        QNetworkReply *reply = manager.get(request);
        connect(reply, &QNetworkReply::finished, this, &OAuthExample::getDataReply);
    }

void OAuthExample::getDataReply()  {
        QNetworkReply *reply = qobject_cast<QNetworkReply *>(sender());
        if (reply->error() == QNetworkReply::NoError) {
            QByteArray response = reply->readAll();
            qDebug() <<"Data respons:"<<response;
        } else {
            qDebug() << "Error: " << reply->errorString();
        }
        reply->deleteLater();

    }




int main(int argc, char *argv[]) {
    QCoreApplication a(argc, argv);
    OAuthExample oauthExample;
    oauthExample.login();

    return a.exec();
}
