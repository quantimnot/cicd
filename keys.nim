import
    std/[
        base64,
        endians,
        streams,
        os,
        strutils,
        math,
        posix
    ],
    pkg/[
        yaml,
        base32,
        nimcrypto,
    ]

type
    Keys* {.sparse.} = object
        onionAddr: string
        secOnionKey: string
        secOnionAuthKey: string
        secSshAuthKey: string
        pubSshAuthKeys: seq[string]
        pubOnionAuthKeys: seq[string]

{.passL: "-lsodium"}
let crypto_pwhash_ALG_ARGON2ID13 {.importc: "crypto_pwhash_ALG_ARGON2ID13", header: "<sodium.h>".}: cint
let crypto_sign_SEEDBYTES {.importc: "crypto_sign_SEEDBYTES", header: "<sodium.h>".}: culonglong
let crypto_pwhash_SALTBYTES {.importc: "crypto_pwhash_SALTBYTES", header: "<sodium.h>".}: cint
let crypto_pwhash_OPSLIMIT_MIN {.importc: "crypto_pwhash_OPSLIMIT_MIN", header: "<sodium.h>".}: culonglong
let crypto_pwhash_MEMLIMIT_MIN {.importc: "crypto_pwhash_MEMLIMIT_MIN", header: "<sodium.h>".}: csize_t
let crypto_scalarmult_curve25519_BYTES {.importc: "crypto_scalarmult_curve25519_BYTES", header: "<sodium.h>".}: cint
let crypto_sign_ed25519_SECRETKEYBYTES {.importc: "crypto_sign_ed25519_SECRETKEYBYTES", header: "<sodium.h>".}: cint
let crypto_sign_ed25519_PUBLICKEYBYTES {.importc: "crypto_sign_ed25519_PUBLICKEYBYTES", header: "<sodium.h>".}: cint
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

proc secEd25519*(seed = ""): string =
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

proc pubEd25519*(secEd25519 = ""): string =
    block:
        var secEd25519 = if secEd25519.len == 0: stdin.readAll else: secEd25519
        if secEd25519.len != crypto_sign_ed25519_SECRETKEYBYTES:
            if secEd25519.len == crypto_sign_ed25519_SECRETKEYBYTES+1 and secEd25519[^1] == '\n':
                secEd25519.removeSuffix '\n'
                doAssert secEd25519.len == 64
            else:
                stderr.writeLine "error: secret ed25519 key size must be " & $crypto_sign_ed25519_SECRETKEYBYTES & " bytes"
                quit 1
        result = newString(crypto_sign_ed25519_PUBLICKEYBYTES)
        doAssert crypto_sign_ed25519_sk_to_pk(result.ptrByte, secEd25519.ptrByte) == 0

proc secOnionAuthKey*(secEd25519 = ""): string =
    block:
        var secEd25519 = if secEd25519.len == 0: stdin.readAll else: secEd25519
        if secEd25519.len != crypto_sign_ed25519_SECRETKEYBYTES:
            if secEd25519.len == crypto_sign_ed25519_SECRETKEYBYTES+1 and secEd25519[^1] == '\n':
                secEd25519.removeSuffix '\n'
                doAssert secEd25519.len == 64
            else:
                stderr.writeLine "error: secret ed25519 key size must be " & $crypto_sign_ed25519_SECRETKEYBYTES & " bytes"
                quit 1
        result = newString(crypto_sign_ed25519_SECRETKEYBYTES)
        doAssert crypto_sign_ed25519_sk_to_curve25519(result.ptrByte, secEd25519.ptrByte) == 0
        result = base32.encode(result)
        result.removeSuffix '='

proc pubOnionAuthKey*(pubEd25519 = ""): string =
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

proc secSshAuthKey*(secEd25519 = "", pubEd25519 = "", comment = ""): string =
    if comment.len == 0:
        stderr.writeLine "error: missing ssh key comment"
        quit 1
    block:
        var secEd25519 = if secEd25519.len == 0: stdin.readAll else: secEd25519
        if secEd25519.len != crypto_sign_ed25519_SECRETKEYBYTES:
            if secEd25519.len == crypto_sign_ed25519_SECRETKEYBYTES+1 and secEd25519[^1] == '\n':
                secEd25519.removeSuffix '\n'
                doAssert secEd25519.len == 64
            else:
                stderr.writeLine "error: secret ed25519 key size must be " & $crypto_sign_ed25519_SECRETKEYBYTES & " bytes"
                quit 1
        var pubEd25519 =
            if pubEd25519.len == 0:
                pubEd25519(secEd25519)
            else:
                pubEd25519

        func secSectLen(): int =
            8 + 4 + 11 + 4 + 32 + 4 + 64 + 4 + comment.len
        func padLen(): int =
            secSectLen() mod 8
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
            (secSectLen() + padLen()).i2s &        # remaining length
            "\x00\x00\x00\x00\x00\x00\x00\x00" &    # checksum used when key is encrypted
            "\x00\x00\x00\x0b" & "ssh-ed25519" &    # key type
            "\x00\x00\x00\x20" & pubEd25519 &       # public key
            "\x00\x00\x00\x40" & secEd25519 &      # secret key
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

proc secOnionKey*(secEd25519 = ""): string =
    block:
        var secEd25519 = if secEd25519.len == 0: stdin.readAll else: secEd25519
        if secEd25519.len != crypto_sign_ed25519_SECRETKEYBYTES:
            if secEd25519.len == crypto_sign_ed25519_SECRETKEYBYTES+1 and secEd25519[^1] == '\n':
                secEd25519.removeSuffix '\n'
                doAssert secEd25519.len == 64
            else:
                stderr.writeLine "error: secret ed25519 key size must be " & $crypto_sign_ed25519_SECRETKEYBYTES & " bytes"
                quit 1
        "== ed25519v1-secret: type0 ==\0\0\0" & secEd25519

proc all*(passwd = "", comment = "*"): string =
    block:
        var passwd = if passwd.len == 0: stdin.readAll else: passwd
        let seed = kdf passwd
        let secEd25519 = secEd25519 seed
        let pubEd25519 = pubEd25519 secEd25519
        var keys: Keys
        keys.secOnionKey = secOnionKey secEd25519
        keys.onionAddr = onionAddr pubEd25519
        keys.secSshAuthKey = secSshAuthKey(secEd25519, pubEd25519, comment)
        # keys.secOnionKey = pubSsh
        keys.secOnionAuthKey = secOnionAuthKey secEd25519
        keys.pubOnionAuthKeys.add pubOnionAuthKey pubEd25519

#     # stderr.writeLine:
#     #     "Client-side:\n" &
#     #     "  Add this to your 'torrc' file: ClientOnionAuthDir CHOOSE/A/DIR\n" &
#     #     "  Restart tor.\n" &
#     #     "  Create a file named '.auth_private' in the chosen ClientOnionAuthDir directory.\n" &
#     #     "  Add this line to that file: " & keys.srvAddr.get[0..^7] & ":descriptor:x25519:" & keys.secOnionAuthKey.get &
#     #     "\n\n" &
#     #     "  Connect to the SSH service like this:\n" &
#     #     "    ssh -oUpdateHostKeys=no -oProxyCommand='nc -x 127.0.0.1:9150 %h %p' -oPubkeyAuthentication=yes -i " & keys.srvAddr.get[0..^7] & "_ssh runner@" & keys.srvAddr.get

proc pgp*(secEd25519 = ""): string =
    # https://github.com/skeeto/passphrase2pgp
    block:
        var secEd25519 = if secEd25519.len == 0: stdin.readAll else: secEd25519
        if secEd25519.len != crypto_sign_ed25519_SECRETKEYBYTES:
            if secEd25519.len == crypto_sign_ed25519_SECRETKEYBYTES+1 and secEd25519[^1] == '\n':
                secEd25519.removeSuffix '\n'
                doAssert secEd25519.len == 64
            else:
                stderr.writeLine "error: secret ed25519 key size must be " & $crypto_sign_ed25519_SECRETKEYBYTES & " bytes"
                quit 1
        var created, expires: int64
        var userId = ""
        # TODO


proc x509*(): string =
    # https://github.com/ahf/onion-x509
    # TODO
    discard

proc installSsh*(file = "") =
    var keys: Keys
    if file.len > 0:
        load(newFileStream(file), keys)
    else:
        load(newFileStream(stdin), keys)
    discard umask(0o077.Mode)
    if keys.pubSshAuthKeys.len > 0:
        createDir(getHomeDir()/".ssh/")
        var authorizedKeys = open(getHomeDir()/".ssh/authorized_keys", fmAppend)
        for key in keys.pubSshAuthKeys:
            authorizedKeys.writeLine(key)
    quit 1

proc installOnion*(file = "", path: string) =
    var keys: Keys
    if file.len > 0:
        load(newFileStream(file), keys)
    else:
        load(newFileStream(stdin), keys)
    discard umask(0o077.Mode)
    if keys.onionAddr.len > 0 and keys.secOnionKey.len > 0:
        writeFile(path/"hs_ed25519_secret_key", base64.decode(keys.secOnionKey))
        writeFile(path/"hostname", keys.onionAddr & '\n')
    else:
        echo readFile path/"hostname"
    if keys.pubOnionAuthKeys.len > 0:
        createDir(path/"authorized_clients")
        for authKey in keys.pubOnionAuthKeys:
            writeFile(path/"authorized_clients"/($blake2_256.digest(authKey) & ".auth"), authKey)

when isMainModule:
    import pkg/cligen
    dispatchMulti(
        [onionAddr],
        [secOnionKey],
        [secEd25519],
        [pubEd25519],
        [secOnionAuthKey],
        [pubOnionAuthKey],
        [secSshAuthKey],
        [kdf],
        [all],
        [installOnion, cmdName = "install-onion", help={"file": "keys file", "path": "Onion hidden service directory"}],
        [installSsh, cmdName = "install-ssh", help={"file": "keys file"}],
    )
