# Description
This project is designed to authenticate users to the Web service using contactless smart cards. As an authentication protocol was chosen protocol OPACITY. This protocol has been specifically designed for contactless payments and now it is officially registered as an authentication protocol ISO/IEC 24727-6.

## Scheme of the protocol of registration and authorization
At registration on a smart card and Web service in advance generated keys of PK and SK are stored. All process of registration consists of eight steps. The scheme of the protocol for registration of the user on Web service:

![Image alt](https://github.com/shevelevsergey/opacity-for-smartcard/raw/master/image/reg.png)

At authorization on a smart card keys of PKs and SKs, a set of public keys of Web services, their webID identifiers and identifiers of the smart card of idC are stored. On Web service keys of PKw and SKw, a set of public keys of users (smart cards) and idC identifiers are stored. All process of authorization consists of seven steps. The scheme of the protocol for authorization of the user on Web service:

![Image alt](https://github.com/shevelevsergey/opacity-for-smartcard/raw/master/image/auth.png)

## Testing
For testing it is required:
- Oracle JDK 1.6+
- NFC Reader ACR 122U (or any other supporting PC\SC)
- Smart Card NXP JCOP J3A081 (Dual Interface)

The project consists of two main parts: host application and java card applet.

The host application represents java the project. For realization standard opportunities of the java language (for example, package `javax.smartcardio.*`) and BouncyCastle cryptoprovider. For start simply download host applications the project from the _/hostapplication_ folder.

Also it is required to install cap the file (applet) on a smart card which can be downloaded from the _/smartcard_ folder.

## Links
- [OPACITY overview](http://www.smartcardalliance.org/resources/pdf/OPACITY_Overview%203.8.pdf)
- [OPACITY protocol specification](http://www.smartcardalliance.org/resources/pdf/OPACITY_Protocol_3.7.pdf)
- [A Cryptographic Analysis of OPACITY](https://eprint.iacr.org/2013/234.pdf)
- [Java Card](http://www.oracle.com/technetwork/java/embedded/javacard/overview/index.html)
- [PC/SC Workgroup Specifications Overview](http://www.pcscworkgroup.com/specifications/overview.php)
