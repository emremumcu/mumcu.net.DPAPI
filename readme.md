# DPAPI (Data Protection Application Programming Interface)

DPAPI (Data Protection Application Programming Interface) is a simple cryptographic application programming interface available as a built-in component in Windows 2000 and later versions of Microsoft Windows operating systems. In theory the Data Protection API can enable symmetric encryption of any kind of data; in practice, its primary use in the Windows operating system is to perform symmetric encryption of asymmetric private keys, using a user or system secret as a significant contribution of entropy.

DPAPI doesn't store any persistent data for itself; instead, it simply receives plaintext and returns ciphertext (or vice versa).

DPAPI security relies upon the Windows operating system's ability to protect the Master Key and RSA private keys from compromise, which in most attack scenarios is most highly reliant on the security of the end user's credentials. A main encryption/decryption key is derived from user's password by PBKDF2 function.

# mumcu.net.DPAPI

mumcu.net.DPAPI is only a wrapper project which allows users to use the functionality originally created by [OBVIEX](https://github.com/obviex).

# References

* [https://en.wikipedia.org/wiki/Data_Protection_API](https://en.wikipedia.org/wiki/Data_Protection_API)
* [https://github.com/obviex/Samples/blob/master/Dpapi.md](https://github.com/obviex/Samples/blob/master/Dpapi.md)