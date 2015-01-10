Haox
====

Haox aims for a Java Kerberos binding, and provides richful, inituitive and interoperable implementation, library and various facilities that integrate Kerberos, PKI and token (OAuth) as desired in modern environments such as mobile, cloud and Hadoop. 

### The Initiatives/Goals 
* Aims as a Java Kerberos binding, with richful and integrated facilities that integrate Kerberos, PKI and token (OAuth) for both client and server sides.
+ Provides client APIs in Kerberos protocol level to interact with a KDC server thru AS and TGS exchanges.
+ Provides an embeded KDC server that applications can easily integrate into products, unit tests or integration tests.
+ Supports FAST/Preauthentication framework to allow popular and useful authentication mechanisms.
+ Supports PKINIT mechanism to allow clients to request tickets using x509 certificate credential.
+ Supports Token Preauth mechanism to allow clients to request tickets using JWT tokens.
+ Provides support for JAAS, GSSAPI and SASL frameworks that applications can leverage.
+ Least dependency, the core part is ensured to depend only on JRE, for easy use and maintain.

### Update
We’re collaborating with ApacheDS community and preparing this project to be ready for a sub project. Feedback is welcome.

### Status
As follows, with the core and critical parts done, important features are still ongoing.
It's going to release 0.1 version in the early next year. We do not suggest production usage prior to the release.
<pre>
ASN-1 (done)
Kerberos core and codec (done)
Kerberos Crypto (done)
Embedded KDC (the core done)
KrbClient (partial APIs done and available)
Preauth/FAST framework (partially done)
Token Preauth (ongoing)
PKINIT (ongoing)
Keytab util (credential cache and keytab support, done)
</pre>

### Desired KrbClient APIs (partialy done)
* Initiate a KrbClient
<pre>
KrbClient krbClient = new KrbClient(kdcHost, kdcPort);
</pre>
* Request a TGT with user plain password credential
<pre>
krbClient.requestTgtTicket(principal, password);
</pre>
* Request a TGT with user x509 certificate credential
<pre>
krbClient.requestTgtTicket(principal, certificate);
</pre>
* Request a TGT with user token credential
<pre>
krbClient.requestTgtTicket(principal, kerbToken);
</pre>
* Request a service ticket with user TGT credential for a server
<pre>
krbClient.requestServiceTicket(tgt, serverPrincipal);
</pre>
* Request a service ticket with user AccessToken credential for a server
<pre>
krbClient.requestServiceTicket(accessToken, serverPrincipal);
</pre>

### The ASN-1 support
Please look at [haox-asn1](https://github.com/drankye/haox/blob/master/haox-asn1/README.md) for details.

### Kerberos Crypto and Encryption Types
Implementing des, des3, rc4, aes, camellia encryption and corresponding checksum types
Interoperates with MIT Kerberos and Microsoft AD
Independent with Kerberos codes in JRE, but rely on JCE

| Encryption Type | Description |
| --------------- | ----------- |
| des-cbc-crc | DES cbc mode with CRC-32 (weak) |
| des-cbc-md4 | DES cbc mode with RSA-MD4 (weak) |
| des-cbc-md5 |	DES cbc mode with RSA-MD5 (weak) |
| des3-cbc-sha1 des3-hmac-sha1 des3-cbc-sha1-kd |	Triple DES cbc mode with HMAC/sha1 |
| des-hmac-sha1 |	DES with HMAC/sha1 (weak) |
| aes256-cts-hmac-sha1-96 aes256-cts AES-256 	| CTS mode with 96-bit SHA-1 HMAC |
| aes128-cts-hmac-sha1-96 aes128-cts AES-128 	| CTS mode with 96-bit SHA-1 HMAC |
| arcfour-hmac rc4-hmac arcfour-hmac-md5 |	RC4 with HMAC/MD5 |
| arcfour-hmac-exp rc4-hmac-exp arcfour-hmac-md5-exp |	Exportable RC4 with HMAC/MD5 (weak) |
| camellia256-cts-cmac camellia256-cts |	Camellia-256 CTS mode with CMAC |
| camellia128-cts-cmac camellia128-cts |	Camellia-128 CTS mode with CMAC |
| des |	The DES family: des-cbc-crc, des-cbc-md5, and des-cbc-md4 (weak) |
| des3 |	The triple DES family: des3-cbc-sha1 |
| aes |	The AES family: aes256-cts-hmac-sha1-96 and aes128-cts-hmac-sha1-96 |
| rc4 |	The RC4 family: arcfour-hmac |
| camellia | The Camellia family: camellia256-cts-cmac and camellia128-cts-cmac |

### Dependency
The core part is ensured to only depend on JRE. Every external dependency is taken carefully and maintained separately.

##### Contrib Projects
- haox-asn1. A model driven ASN-1 encoding and decoding framework
- haox-event. A pure event driven application framework aiming to construct applications of asynchronous and concurrent handlers. It includes UDP and TCP transport based on pure Java NIO and concurrency pattern.
- haox-config. A unified configuration API that aims to support various configuration file formats, like XML, JNI, CSV and Java Properties file.
- haox-token. Implements a JWT token API for Kerberos that's defined in TokenPreauth drafts.

### License
Apache License V2.0
