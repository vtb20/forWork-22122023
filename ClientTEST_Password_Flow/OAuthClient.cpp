#include "OAuthClient.h"
#include "o0globals.h"
#include "o0settingsstore.h"
#include "o2requestor.h"
#include <QCoreApplication>

OAuthClient::OAuthClient(QObject *parent) : QObject(parent) {
    manager = new QNetworkAccessManager(this);
    o2 = new O2(this);


    connect(o2, SIGNAL(linkedChanged()), this, SLOT(onLinkedChanged()));
    o2->setClientId("12345");
    o2->setUsername("vtb");
    o2->setPassword("vtb");
    o2->setScope("admin");
    o2->setTokenUrl("http://127.0.0.1:8080/o/oauth2/token");
    o2->setGrantFlow(O2::GrantFlowResourceOwnerPasswordCredentials);

    O0SettingsStore *store = new O0SettingsStore(O2_ENCRYPTION_KEY);
    store->setGroupKey("clientTest3");
    o2->setStore(store);
    qDebug()<<store;
    // Start the OAuth process
    o2->unlink();
    o2->link();
}
void OAuthClient::onLinkedChanged() {
    qDebug() << "Linked changed:" << o2->linked();
    if (o2->linked()) {
        // Once linked, perform actions here
        qDebug() << "Access Token:" << o2->token().toUtf8();
        getData();
    }
}

void OAuthClient::getData() {
    QNetworkRequest request(QUrl("http://127.0.0.1:8080/o/oauth2/example"));
    request.setRawHeader("Authorization", "Bearer " + o2->token().toUtf8());
    QNetworkReply *reply = manager->get(request);

    QEventLoop loop;
    connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
    loop.exec();

    if (reply->error() == QNetworkReply::NoError) {
        QByteArray responseData = reply->readAll();
        qDebug() << "Data:" << responseData;
        QCoreApplication::quit();
    } else {
        qDebug() << "Error:" << reply->errorString();
    }

    reply->deleteLater();
}
