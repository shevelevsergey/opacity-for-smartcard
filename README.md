# Description
This project is designed to authenticate users to the Web service using contactless smart cards. As an authentication protocol was chosen protocol OPACITY. This protocol has been specifically designed for contactless payments and now it is officially registered as an authentication protocol ISO/IEC 24727-6.

## Scheme of the protocol of registration and authorization

At registration on a smart card and Web service in advance generated keys of PK and SK are stored. All process of registration consists of eight steps. The scheme of the protocol for registration of the user on Web service:

![Image alt](https://github.com/shevelevsergey/opacity-for-smartcard/raw/master/image/reg.png)

At authorization on a smart card keys of PKs and SKs, a set of public keys of Web services, their webID identifiers and identifiers of the smart card of idC are stored. On Web service keys of PKw and SKw, a set of public keys of users (smart cards) and idC identifiers are stored. All process of authorization consists of seven steps. The scheme of the protocol for authorization of the user on Web service:

![Image alt](https://github.com/shevelevsergey/opacity-for-smartcard/raw/master/image/auth.png)
