#ifndef SESSIONAPI_H
#define SESSIONAPI_H
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>

class SessionAPI
{ public:
    static QSqlDatabase getDatabaseConnection(const QString& connectionName = "SessionAPIConnection") {
        QSqlDatabase db;
        if (QSqlDatabase::contains(connectionName)) {
            db = QSqlDatabase::database(connectionName);
        } else {
            db = QSqlDatabase::addDatabase("QMYSQL", connectionName);
            db.setHostName("localhost");
            db.setDatabaseName("work1");
            db.setUserName("root");
            db.setPassword("@Vtb28042002");
            if (!db.open()) {
                qDebug() << "Không thể kết nối tới cơ sở dữ liệu:" << db.lastError().text();
            }
        }
        return db;
    }



};



#endif // SESSIONAPI_H
