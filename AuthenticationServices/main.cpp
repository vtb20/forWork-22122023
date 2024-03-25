#include <QtCore/QCoreApplication>
#include <QDebug>
#include <QHostAddress>
#include <QHttpServer>
#include "User.h"
#include "AuthMiddleware.h"

void protectedRoute(QHttpServer &httpServer, const QString &path, QHttpServerRequest::Method method,
                    const std::function<QHttpServerResponse(const QHttpServerRequest &)> &handler,
                    Middleware &middleware)
{
    httpServer.route(path, method, [&middleware, &handler](const QHttpServerRequest &request) {
        auto result = middleware.checkingToken(request);
        if (result.statusCode() == QHttpServerResponse::StatusCode::Continue) {
            return handler(request);
        } else {
            return result;
        }
    });
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    Middleware MiddlewareController;
    User User;
    QHttpServer httpServer;
    // static const char *GftEndpoint = "https://accounts.google.com/o/oauth2/auth";
    // static const char *GftTokenUrl = "https://accounts.google.com/o/oauth2/token";
    // static const char *GftRefreshUrl = "https://accounts.google.com/o/oauth2/token";

    //Route for User:

    httpServer.route("/o/oauth2/token", QHttpServerRequest::Method::Post,
                     [&User](const QHttpServerRequest &request) { return User.LoginRequest(request); });

    httpServer.route("/api/auth/register", QHttpServerRequest::Method::Post,
                     [&User](const QHttpServerRequest &request) { return User.Register(request); });

    httpServer.route("/api/auth/refreshtoken", QHttpServerRequest::Method::Get,
                     [&User](const QHttpServerRequest &request) { return User.handlerfToken(request); });
   //Thêm URL mới trả về data cho client
    protectedRoute(httpServer,"/o/oauth2/example", QHttpServerRequest::Method::Get,
        [&User](const QHttpServerRequest &request) { return User.Example(request); }, MiddlewareController);

    protectedRoute(httpServer,"/api/auth/logout", QHttpServerRequest::Method::Delete,
        [&User](const QHttpServerRequest &request) { return User.Logout(request); }, MiddlewareController);

    const auto port = httpServer.listen(QHostAddress::Any, 8080);
    if (!port) {
        qWarning() << "Server failed to listen on a port.";
        return 0;
    }

    qDebug() << "Running on http://127.0.0.1:" << port;
    return app.exec();
}
