#ifndef DATABASECONNECTION_H
#define DATABASECONNECTION_H

#include <QSqlDatabase>
#include <QSqlError>
#include <QDebug>

class DatabaseConnection {
public:
    static QSqlDatabase connect(const QString& connectionName = "SessionAPIConnection") {
        QSqlDatabase db = QSqlDatabase::contains(connectionName) ? QSqlDatabase::database(connectionName) :
                              QSqlDatabase::addDatabase("QMYSQL", connectionName);

        if (!db.isOpen()) {
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

#endif // DATABASECONNECTION_H
