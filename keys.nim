import std/[base64, osproc, endians, streams, os, strutils, math, httpclient, json]
import
    pkg/[
        yaml,
        base32,
        nimcrypto,
    ]

type
    Keys* {.sparse.} = object
        srvAddr: Option[string]
        pubSrvKey: Option[string]
        privSrvKey: Option[string]
        privAuthKeyPem: Option[string]
        privAuthKey: Option[string]
        privSshKey: Option[string]
        pubSshKeys: seq[string]
        pubAuthKeys: seq[string]

{.passL: "-lsodium"}
let crypto_pwhash_ALG_ARGON2ID13 {.importc: "crypto_pwhash_ALG_ARGON2ID13", header: "<sodium.h>".}: cint
let crypto_sign_SEEDBYTES {.importc: "crypto_sign_SEEDBYTES", header: "<sodium.h>".}: culonglong
let crypto_pwhash_SALTBYTES {.importc: "crypto_pwhash_SALTBYTES", header: "<sodium.h>".}: cint
let crypto_pwhash_OPSLIMIT_MIN {.importc: "crypto_pwhash_OPSLIMIT_MIN", header: "<sodium.h>".}: culonglong
let crypto_pwhash_MEMLIMIT_MIN {.importc: "crypto_pwhash_MEMLIMIT_MIN", header: "<sodium.h>".}: csize_t
let crypto_box_SEALBYTES {.importc: "crypto_box_SEALBYTES", header: "<sodium.h>".}: cint
let crypto_scalarmult_curve25519_BYTES {.importc: "crypto_scalarmult_curve25519_BYTES", header: "<sodium.h>".}: cint
let crypto_sign_ed25519_SECRETKEYBYTES {.importc: "crypto_sign_ed25519_SECRETKEYBYTES", header: "<sodium.h>".}: cint
let crypto_sign_ed25519_PUBLICKEYBYTES {.importc: "crypto_sign_ed25519_PUBLICKEYBYTES", header: "<sodium.h>".}: cint
proc crypto_box_seal(c: ptr byte, m: ptr byte, mlen: uint64, pk: ptr byte): cint {.nodecl, importc.}
proc crypto_sign_ed25519_pk_to_curve25519(x25519_pk, ed25519_pk: ptr byte): cint {.nodecl, importc.}
proc crypto_sign_ed25519_sk_to_curve25519(x25519_sk, ed25519_skpk: ptr byte): cint {.nodecl, importc.}
proc crypto_sign_seed_keypair(pk, sk, seed: ptr byte): cint {.nodecl, importc.}
proc crypto_sign_ed25519_sk_to_pk(pk, sk: ptr byte): cint {.nodecl, importc.}
proc crypto_pwhash(
    output: ptr byte,
    outlen: culonglong,
    passwd: ptr byte,
    passwdlen: culonglong,
    salt: ptr byte,
    opslimit: culonglong,
    memlimit: csize_t,
    alg: cint
): cint {.nodecl, importc.}

template ptrByte(buffer): untyped = cast[ptr byte](unsafeAddr buffer[0])

proc kdf*(passwd = ""): string =
    # https://libsodium.gitbook.io/doc/password_hashing/default_phf
    block:
        var passwd = if passwd.len == 0: stdin.readAll else: passwd
        result = newString crypto_sign_SEEDBYTES
        var salt = newString crypto_pwhash_SALTBYTES
        doAssert crypto_pwhash(
            result.ptrByte, crypto_sign_SEEDBYTES,
            passwd.ptrByte, passwd.len.culonglong,
            salt.ptrByte, crypto_pwhash_OPSLIMIT_MIN,
            crypto_pwhash_MEMLIMIT_MIN, crypto_pwhash_ALG_ARGON2ID13) == 0

proc privEd25519*(seed = ""): string =
    # https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519
    block:
        var seed = if seed.len == 0: stdin.readAll else: seed
        if seed.len.culonglong != crypto_sign_SEEDBYTES:
            if seed.len.culonglong == crypto_sign_SEEDBYTES+1 and seed[^1] == '\n':
                seed.removeSuffix '\n'
                doAssert seed.len == 32
            else:
                stderr.writeLine "error: seed size must be " & $crypto_sign_SEEDBYTES & " bytes"
                quit 1
        var pk = newString(crypto_sign_ed25519_PUBLICKEYBYTES)
        result = newString(crypto_sign_ed25519_SECRETKEYBYTES)
        doAssert crypto_sign_seed_keypair(pk.ptrByte, result.ptrByte, seed.ptrByte) == 0

proc pubEd25519*(privEd25519 = ""): string =
    block:
        var privEd25519 = if privEd25519.len == 0: stdin.readAll else: privEd25519
        if privEd25519.len != crypto_sign_ed25519_SECRETKEYBYTES:
            if privEd25519.len == crypto_sign_ed25519_SECRETKEYBYTES+1 and privEd25519[^1] == '\n':
                privEd25519.removeSuffix '\n'
                doAssert privEd25519.len == 64
            else:
                stderr.writeLine "error: private ed25519 key size must be " & $crypto_sign_ed25519_SECRETKEYBYTES & " bytes"
                quit 1
        result = newString(crypto_sign_ed25519_PUBLICKEYBYTES)
        doAssert crypto_sign_ed25519_sk_to_pk(result.ptrByte, privEd25519.ptrByte) == 0

proc privX25519*(privEd25519 = ""): string =
    block:
        var privEd25519 = if privEd25519.len == 0: stdin.readAll else: privEd25519
        if privEd25519.len != crypto_sign_ed25519_SECRETKEYBYTES:
            if privEd25519.len == crypto_sign_ed25519_SECRETKEYBYTES+1 and privEd25519[^1] == '\n':
                privEd25519.removeSuffix '\n'
                doAssert privEd25519.len == 64
            else:
                stderr.writeLine "error: private ed25519 key size must be " & $crypto_sign_ed25519_SECRETKEYBYTES & " bytes"
                quit 1
        result = newString(crypto_sign_ed25519_SECRETKEYBYTES)
        doAssert crypto_sign_ed25519_sk_to_curve25519(result.ptrByte, privEd25519.ptrByte) == 0
        result = base32.encode(result)
        result.removeSuffix '='

proc pubX25519*(pubEd25519 = ""): string =
    block:
        var pubEd25519 = if pubEd25519.len == 0: stdin.readAll else: pubEd25519
        if pubEd25519.len != crypto_sign_ed25519_PUBLICKEYBYTES:
            if pubEd25519.len == crypto_sign_ed25519_PUBLICKEYBYTES+1 and pubEd25519[^1] == '\n':
                pubEd25519.removeSuffix '\n'
                doAssert pubEd25519.len == 32
            else:
                stderr.writeLine "error: public ed25519 key size must be " & $crypto_sign_ed25519_PUBLICKEYBYTES & " bytes"
                quit 1
        result = newString(crypto_sign_ed25519_PUBLICKEYBYTES)
        doAssert crypto_sign_ed25519_pk_to_curve25519(result.ptrByte, pubEd25519.ptrByte) == 0
        result = "descriptor:x25519:" & base32.encode(result)
        result.removeSuffix '='

proc privSsh*(privEd25519 = "", pubEd25519 = "", comment = ""): string =
    if comment.len == 0:
        stderr.writeLine "error: missing ssh key comment"
        quit 1
    block:
        var privEd25519 = if privEd25519.len == 0: stdin.readAll else: privEd25519
        if privEd25519.len != crypto_sign_ed25519_SECRETKEYBYTES:
            if privEd25519.len == crypto_sign_ed25519_SECRETKEYBYTES+1 and privEd25519[^1] == '\n':
                privEd25519.removeSuffix '\n'
                doAssert privEd25519.len == 64
            else:
                stderr.writeLine "error: private ed25519 key size must be " & $crypto_sign_ed25519_SECRETKEYBYTES & " bytes"
                quit 1
        var pubEd25519 =
            if pubEd25519.len == 0:
                pubEd25519(privEd25519)
            else:
                pubEd25519

        func privSectLen(): int =
            8 + 4 + 11 + 4 + 32 + 4 + 64 + 4 + comment.len
        func padLen(): int =
            privSectLen() mod 8
        func padding(): string =
            for n in 1..padLen():
                result &= cast[char](n)
        func i2s(i: int): string =
            result = newString 4
            (result[0]).addr.bigEndian32 i.unsafeAddr
        proc opensshKey(): string =
            result = "openssh-key-v1" & '\x00' &    # NULL-terminated "Auth Magic" string
            "\x00\x00\x00\x04" & "none" &           # ciphername length and string
            "\x00\x00\x00\x04" & "none" &           # kdfname length and string
            "\x00\x00\x00\x00" &                    # kdf (0 length, no kdf)
            "\x00\x00\x00\x01" &                    # number of keys, hard-coded to 1 (no length)
            "\x00\x00\x00\x33" &                    # public key length in ssh format
            "\x00\x00\x00\x0b" & "ssh-ed25519" &    # key type
            "\x00\x00\x00\x20" & pubEd25519 &       # public key
            (privSectLen() + padLen()).i2s &        # remaining length
            "\x00\x00\x00\x00\x00\x00\x00\x00" &    # checksum used when key is encrypted
            "\x00\x00\x00\x0b" & "ssh-ed25519" &    # key type
            "\x00\x00\x00\x20" & pubEd25519 &       # public key
            "\x00\x00\x00\x40" & privEd25519 &      # private key
            comment.len.i2s & comment &             # comment
            padding()                               # pad to block size
            result = base64.encode(result)
            for n in 1..floorDiv(result.len, 70):
                result.insert("\n", (n * 70) + (n-1))
            result.removeSuffix '='
        result =
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" &
            opensshKey() &
            "\n-----END OPENSSH PRIVATE KEY-----\n"

proc onionAddr*(pubEd25519 = ""): string =
    # from: https://gitweb.torproject.org/torspec.git/tree/address-spec.txt
    #   onion_address = base32(PUBKEY | CHECKSUM | VERSION)
    #   CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
    #   where:
    #     - PUBKEY is the 32 bytes ed25519 master pubkey of the onion service.
    #     - VERSION is a one byte version field (default value '\x03')
    #     - ".onion checksum" is a constant string
    #     - CHECKSUM is truncated to two bytes before inserting it in onion_address
    block:
        var pubEd25519 = if pubEd25519.len == 0: stdin.readAll else: pubEd25519
        if pubEd25519.len != crypto_sign_ed25519_PUBLICKEYBYTES:
            if pubEd25519.len == crypto_sign_ed25519_PUBLICKEYBYTES+1 and pubEd25519[^1] == '\n':
                pubEd25519.removeSuffix '\n'
                doAssert pubEd25519.len == 32
            else:
                stderr.writeLine "error: public ed25519 key size must be " & $crypto_sign_ed25519_PUBLICKEYBYTES & " bytes"
                quit 1
        const ver: char = '\x03'
        let sum = ($keccak_512.digest(".onion checksum" & pubEd25519 & ver))[0..1]
        base32.encode(pubEd25519 & sum & ver).toLowerAscii & ".onion"

proc privOnionKey*(privEd25519 = ""): string =
    block:
        var privEd25519 = if privEd25519.len == 0: stdin.readAll else: privEd25519
        if privEd25519.len != crypto_sign_ed25519_SECRETKEYBYTES:
            if privEd25519.len == crypto_sign_ed25519_SECRETKEYBYTES+1 and privEd25519[^1] == '\n':
                privEd25519.removeSuffix '\n'
                doAssert privEd25519.len == 64
            else:
                stderr.writeLine "error: private ed25519 key size must be " & $crypto_sign_ed25519_SECRETKEYBYTES & " bytes"
                quit 1
        "== ed25519v1-secret: type0 ==\0\0\0" & privEd25519

proc all*(passwd = "") =
    block:
        var passwd = if passwd.len == 0: stdin.readAll else: passwd
        let seed = kdf passwd
        let privEd25519 = privEd25519 seed
        let pubEd25519 = pubEd25519 privEd25519
        let privX25519 = privX25519 privEd25519
        let pubX25519 = pubX25519 pubEd25519
        let privOnionKey = privOnionKey privEd25519
        let onionAddr = onionAddr pubEd25519
        let privSsh = privSsh(privEd25519, pubEd25519, "t")
        "hs_ed25519_secret_key".writeFile privOnionKey
        "hostname".writeFile onionAddr
        "ssh".writeFile privSsh
        # "ssh.pub".writeFile pubSsh
        "auth".writeFile privX25519
        (onionAddr[0..^7] & ".auth").writeFile pubX25519

#     # stderr.writeLine:
#     #     "Client-side:\n" &
#     #     "  Add this to your 'torrc' file: ClientOnionAuthDir CHOOSE/A/DIR\n" &
#     #     "  Restart tor.\n" &
#     #     "  Create a file named '.auth_private' in the chosen ClientOnionAuthDir directory.\n" &
#     #     "  Add this line to that file: " & keys.srvAddr.get[0..^7] & ":descriptor:x25519:" & keys.privAuthKey.get &
#     #     "\n\n" &
#     #     "  Connect to the SSH service like this:\n" &
#     #     "    ssh -oUpdateHostKeys=no -oProxyCommand='nc -x 127.0.0.1:9150 %h %p' -oPubkeyAuthentication=yes -i " & keys.srvAddr.get[0..^7] & "_ssh runner@" & keys.srvAddr.get

proc pgp*(privEd25519 = ""): string =
    # https://github.com/skeeto/passphrase2pgp
    block:
        var privEd25519 = if privEd25519.len == 0: stdin.readAll else: privEd25519
        if privEd25519.len != crypto_sign_ed25519_SECRETKEYBYTES:
            if privEd25519.len == crypto_sign_ed25519_SECRETKEYBYTES+1 and privEd25519[^1] == '\n':
                privEd25519.removeSuffix '\n'
                doAssert privEd25519.len == 64
            else:
                stderr.writeLine "error: private ed25519 key size must be " & $crypto_sign_ed25519_SECRETKEYBYTES & " bytes"
                quit 1
        var created, expires: int64
        var userId = ""
        # TODO


proc x509*(): string =
    # https://github.com/ahf/onion-x509
    discard

proc installSsh*(file = "") =
    var keys: Keys
    if file.len > 0:
        load(newFileStream(file), keys)
    else:
        load(newFileStream(stdin), keys)
    if keys.pubSshKeys.len > 0:
        createDir(getHomeDir()/".ssh/")
        discard execCmd("chmod 0700 ~/.ssh")
        var authorizedKeys = open(getHomeDir()/".ssh/authorized_keys", fmAppend)
        for key in keys.pubSshKeys:
            authorizedKeys.writeLine(key)
        discard execCmd("chmod 0600 ~/.ssh/authorized_keys")
    quit 2

proc installOnion*(file = "", path: string) =
    var keys: Keys
    if file.len > 0:
        load(newFileStream(file), keys)
    else:
        load(newFileStream(stdin), keys)
    if keys.srvAddr.isSome and keys.privAuthKey.isSome:
        writeFile(path/"hs_ed25519_secret_key", base64.decode(keys.privSrvKey.get))
        writeFile(path/"hostname", keys.srvAddr.get & '\n')
    else:
        echo readFile path/"hostname"
    if keys.pubAuthKeys.len > 0:
        createDir(path/"authorized_clients")
        discard execCmd("chmod 0700 " & path)
        discard execCmd("chmod 0700 " & path/"authorized_clients")
        var n = 'a'
        for authKey in keys.pubAuthKeys:
            writeFile(path/"authorized_clients"/(n & ".auth"), authKey)
            discard execCmd("chmod u=r,go= " & path/"authorized_clients"/(n & ".auth"))
            n.inc

proc upload*(file: string, repo, user: string, randomAddr = true, auth = true, ssh = true) =
    var keys: Keys
    if file.len > 0:
        load(newFileStream(file), keys)
    else:
        load(newFileStream(stdin), keys)

    # Clear fields we don't want to upload
    keys.privAuthKeyPem = none string
    keys.privAuthKey = none string
    keys.privSshKey = none string
    if randomAddr:
        keys.srvAddr = none string
    if not auth:
        keys.pubAuthKeys = @[]
    if not ssh:
        keys.pubSshKeys = @[]

    var keysYml = keys.dump(tsNone, asTidy)
    doAssert existsEnv("GITHUB_TOKEN"), "`GITHUB_TOKEN` environment variable needs set"
    var client = newHttpClient()
    var secretName = "debug_keys_" & user
    client.headers.add("Authorization", "token " & getEnv("GITHUB_TOKEN"))
    client.headers.add("Accept", "application/vnd.github.v3+json")
    var repoPublicEncryptionKey = client.getContent("https://api.github.com/repos/" & repo & "/actions/secrets/public-key")
    let keyId = repoPublicEncryptionKey.parseJson()["key_id"].getStr
    repoPublicEncryptionKey = base64.decode(repoPublicEncryptionKey.parseJson()["key"].getStr)
    var ciphertext = newString(crypto_box_SEALBYTES + keysYml.len)
    doAssert crypto_box_seal(ciphertext.ptrByte, keysYml.ptrByte, keysYml.len.uint64, repoPublicEncryptionKey.ptrByte) == 0
    let body = %* {"key_id": keyId, "encrypted_value": base64.encode(ciphertext)}
    let response = client.put("https://api.github.com/repos/" & repo & "/actions/secrets/" & secretName, body = $body)
    doAssert response.code in {Http201, Http204}, response.status

when isMainModule:
    import pkg/cligen
    dispatchMulti(
        [onionAddr],
        [privOnionKey],
        [privEd25519],
        [pubEd25519],
        [privX25519],
        [pubX25519],
        [privSsh],
        [kdf],
        [all],
        [upload, help={
            "file": "keys file",
            "repo": "repo name",
            "user": "user name",
            "randomAddr": "create a random onion address",
            "auth": "use tor authentication",
            "ssh": "enable ssh"
        }],
        [installOnion, cmdName = "install-onion", help={"file": "keys file", "path": "Extract tor service config"}],
        [installSsh, cmdName = "install-ssh", help={"file": "keys file"}],
    )
