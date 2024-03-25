QT += core sql httpserver network

CONFIG += c++17 cmdline

SOURCES += main.cpp

# Default rules for deployment.

target.path = $$[QT_INSTALL_EXAMPLES]/network/threadedfortuneserver
INSTALLS += target

HEADERS += \
    AuthMiddleware.h \
    DatabaseConnection.h \
    TokenManager.h \
    User.h

HEADERS  += ./src/qjsonwebtoken.h
SOURCES  += ./src/qjsonwebtoken.cpp
