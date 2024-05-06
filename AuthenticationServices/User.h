#ifndef USER_H
#define USER_H

#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QDebug>
#include <QCryptographicHash>

class User {

public:
    User(QSqlDatabase &db) : db(db) {}

    void setUsername(const QString &username) {
        this->username = username;
    }

    void setPassword(const QString &password) {
        this->password = password;
    }

    bool authenticationUser() {
        QString hashpass =  hashPassword(password);

        QSqlQuery query(db);
        query.prepare("SELECT * FROM users WHERE name = :username AND password = :password");
        query.bindValue(":username", username);
        query.bindValue(":password", hashpass);

        if (!query.exec()) {
            qDebug() << "Query failed:" << query.lastError().text();
            return false;
        }
        return query.next();
    }

    QString getUserIdByUsername() {
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

private:
    QSqlDatabase &db;
    QString username;
    QString password;

    QString hashPassword(const QString &password) {
        QByteArray passwordBytes = password.toUtf8();
        QByteArray hashedBytes = QCryptographicHash::hash(passwordBytes, QCryptographicHash::Sha256);
        return QString(hashedBytes.toHex());
    }
};

#endif // USER_H
