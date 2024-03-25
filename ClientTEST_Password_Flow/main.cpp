#include <QCoreApplication>
#include "OAuthClient.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    QCoreApplication::setOrganizationName("O2");
    QCoreApplication::setApplicationName("Client Test");
    OAuthClient client;
    return a.exec();
}

