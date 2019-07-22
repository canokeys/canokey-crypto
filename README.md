# Cryptography algorithms

This library defines the APIs that are used by Canokey.

The default implementations are mainly used to test Canokey on PC, which are weakly linked.

We suggest to use a platform dependent implementations (e.g., ST Crypto Lib for STM32 targets) rather than the default ones.

## Ref:

- Mbed Crypto: https://github.com/ARMmbed/mbed-crypto
- SHA2: http://www.aarongifford.com/computers/sha.html
- SHA3: https://github.com/rhash/RHash
