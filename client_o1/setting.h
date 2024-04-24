#ifndef OAUTHEXAMPLE_H
#define OAUTHEXAMPLE_H

#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>

class OAuthExample : public QObject {
    Q_OBJECT

public:
    explicit OAuthExample(QObject *parent = nullptr);

public slots:
    void login();
    void loginReply();
    void getData();
    void getDataReply();

private:
    QNetworkAccessManager manager;
    QByteArray loginResponse;
};

#endif // OAUTHEXAMPLE_H
