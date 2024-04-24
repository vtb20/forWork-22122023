#include <QtCore/QCoreApplication>
#include <QDebug>
#include <QHostAddress>
#include <QHttpServer>
#include "User.h"
#include "AuthMiddleware.h"


void protectedRoute_02(QHttpServer &httpServer, const QString &path, QHttpServerRequest::Method method,
                    const std::function<QHttpServerResponse(const QHttpServerRequest &)> &handler,
                    Middleware &middleware)
{
    httpServer.route(path, method, [&middleware, &handler](const QHttpServerRequest &request) {
        auto result = middleware.checkingToken_O2(request);
        if (result.statusCode() == QHttpServerResponse::StatusCode::Continue) {
            return handler(request);
        } else {
            return result;
        }
    });
}

void protectedRoute_01(QHttpServer &httpServer, const QString &path, QHttpServerRequest::Method method,
                       const std::function<QHttpServerResponse(const QHttpServerRequest &)> &handler,
                       Middleware &middleware)
{
    httpServer.route(path, method, [&middleware, &handler](const QHttpServerRequest &request) {
        auto result = middleware.checkingToken_O1(request);
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

    //Login o2
    httpServer.route("/o/auth2/token", QHttpServerRequest::Method::Post,
                         [&User](const QHttpServerRequest &request) { return User.Login_for_O2(request); });
    //Login o1
    httpServer.route("/o/oauth1/access_token", QHttpServerRequest::Method::Post,
                     [&User] (const QHttpServerRequest &request) {return User.Login_for_O1(request);  });
    //Logout o2
    httpServer.route("/o/auth2/logout", QHttpServerRequest::Method::Post,
                     [&User](const QHttpServerRequest &request) { return User.Logout_o2(request); });
    //Logout o1
    httpServer.route("/o/auth1/logout", QHttpServerRequest::Method::Post,
                     [&User](const QHttpServerRequest &request) { return User.Logout_o1(request); });

    //Refesh token o2
    httpServer.route("/o/auth2/refreshtoken", QHttpServerRequest::Method::Post,
                     [&User](const QHttpServerRequest &request) { return User.handleRereshToken(request); });

    //Thêm URL mới trả về data cho client
    protectedRoute_02(httpServer,"/o/oauth2/example", QHttpServerRequest::Method::Get,
        [&User](const QHttpServerRequest &request) { return User.Example(request); }, MiddlewareController);

    //Xác thực Oauth 1.0
    protectedRoute_01(httpServer,"/o/oauth/example", QHttpServerRequest::Method::Get,
        [&User](const QHttpServerRequest &request) { return User.Example(request); }, MiddlewareController);

    const auto port = httpServer.listen(QHostAddress::Any, 8080);
    if (!port) {
        qWarning() << "Server failed to listen on a port.";
        return 0;
    }

    qDebug() << "Running on http://127.0.0.1:" << port;
    return app.exec();
}
