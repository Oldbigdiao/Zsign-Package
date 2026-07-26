# OpenSSL iOS compatibility build

- Version: OpenSSL 3.5.7 LTS
- Source: https://github.com/openssl/openssl/releases/tag/openssl-3.5.7
- Source archive SHA-256: `a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8`
- Device library SHA-256: `9eff2cbb172ba30f7d8318012fa04fb529371b59e5dbfeb6376f7c6aa0019e56`
- Simulator library SHA-256: `9614605095c3ca7528d37a2151a14f37a8fc6f1d7b64375c55e6d6ab207d316b`
- iOS device minimum: 10.0
- Simulator slices: x86_64 minimum 10.0; arm64 minimum 14.0, matching Apple's arm64 Simulator floor

The XCFramework was built from the official source archive with `no-shared`
and `no-tests`. It contains only iOS device and iOS Simulator static libraries.
The upstream license is preserved in `OpenSSL-LICENSE.txt`.
