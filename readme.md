# CI/CD

## Targets

| build host  | target                    | builds | tests |
|-------------|---------------------------|--------|-------|
| linux       | linux-native              | [ ]    | [ ]   |
| linux       | android-native            | [ ]    | [ ]   |
| linux       | android-sim               | [ ]    | [ ]   |
| linux       | firefox-js                | [ ]    | [ ]   |
| linux       | chrome-js                 | [ ]    | [ ]   |
| linux       | android-chrome-js         | [ ]    | [ ]   |
| linux       | firefox-emscripten        | [ ]    | [ ]   |
| linux       | chrome-emscripten         | [ ]    | [ ]   |
| linux       | android-chrome-emscripten | [ ]    | [ ]   |
| linux       | firefox-wasm              | [ ]    | [ ]   |
| linux       | chrome-wasm               | [ ]    | [ ]   |
| linux       | android-chrome-wasm       | [ ]    | [ ]   |
| macos       | macos-native              | [ ]    | [ ]   |
| macos       | ios-native                | [ ]    | [ ]   |
| macos       | ios-sim                   | [ ]    | [ ]   |
| macos       | safari-js                 | [ ]    | [ ]   |
| macos       | ios-safari-js             | [ ]    | [ ]   |
| macos       | safari-emscripten         | [ ]    | [ ]   |
| macos       | ios-safari-emscripten     | [ ]    | [ ]   |
| macos       | safari-wasm               | [ ]    | [ ]   |
| macos       | ios-safari-wasm           | [ ]    | [ ]   |
| windows     | windows-native            | [ ]    | [ ]   |
| windows     | edge-js                   | [ ]    | [ ]   |
| windows     | edge-emscripten           | [ ]    | [ ]   |
| windows     | edge-wasm                 | [ ]    | [ ]   |

| deploy host | package format            | codesign | endpoint        |
|-------------|---------------------------|----------|-----------------|
| linux       | [ ] tgz, [ ] txz, [ ] zip, [ ] apk | [ ] pgp, [ ] x509  | [ ] GH, [ ] GHP, [ ] CWS, [ ] GP, [ ] GPB, [ ] NIM, [ ] RSYNC          |
| macos       | [ ] tgz, [ ] dmg, [ ] ipa  | [ ] x509      | [ ] AS, [ ] TF, [ ] GH, [ ] GP, [ ] RSYNC  |
| windows     | [ ] zip, [ ] msix | [ ] x509     | [ ] MS          |

| Code  | Endpoint         |
|-------|------------------|
| GH    | GitHub Releases  |
| GHP   | GitHub Pages     |
| CWS   | Chome Web Store  |
| GP    | Google Play      |
| GPB   | Google Play Beta |
| AS    | Apple App Store  |
| TF    | Apple TestFlight |
| MS    | Microsoft Store  |
| NIM   | Nimble           |
| RSYNC | Rsync over SSH   |

| Code  | Codesign             |
|-------|----------------------|
| PGP   | Pretty Good Privacy  |
| X509  | X.509 Certificate    |

## Design Notes

- New commits will cancel running jobs for the same git ref.
- Some dependencies are cached.
  - Caching can be disabled by putting `[nocache ci]` in the commit message.
- Can be skipped by putting `[skip ci]` in the commit message.
- Can be debugged by putting `[debug ci]` or `[debug ci <key_id>]` in the commit message.
  - The `key_id` in the comment matches a GitHub repository secret of the same name.
    - Not specifying a key will match against a repo secret of the form `debug_keys_<github_user>`.
    - The secret is of this form:
      ed25519 private key   <- tor service id key
      x25519 public key     <- auth key
      ...                   <- additional auth keys
    - Keys can be generated using the `keys` utility
  - Creates a Tor ssh service.
  - Creates a Tor http service.
    - Serves build artifacts.
    - Serves code-server (vscode) IDE.
      - Provides code editing and shell access.

Creating a pull request:
  - Builds and runs tests.
  - Builds optimized release artifacts.
  - Runs some tests on the release artifacts.
  - Packages the release artifacts.
  - Outputs the release artifacts.

Pushing to HEAD branch:
  - (same as pull request)
  - Development codesigns artifacts.
  - Deploys artifacts and build metadata to development endpoints.

Creating a tag:
  - (same as pull request)
  - Release codesigns artifacts.
  - Deploys artifacts to release endpoints.

## Platforms

### Linux

#### See Also

### Apple macOS

#### See Also

### Apple iOS

#### See Also

### Google Android

#### See Also

### Microsft Windows

#### See Also

* https://developer.microsoft.com/en-us/microsoft-store/
* https://docs.microsoft.com/en-us/windows/uwp/publish/
* https://gist.github.com/vszakats/7ef9e86506f5add961bae0412ecbe696

### Firefox

#### See Also

### Chrome

#### See Also

### Safari

#### See Also
