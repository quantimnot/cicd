import std/[base64, osproc, posix_utils, streams, os, strutils]
import
    pkg/[
        yaml,
        base32,
    ]

type
    TorKeys* {.sparse.} = object
        srvAddr: string
        privSrvKey: string
        privAuthKeyPem: Option[string]
        privAuthKey: Option[string]
        privSshKey: Option[string]
        pubSshKey: string
        pubAuthKey: string
        pubAuthKeys: seq[string]

when defined uploader:
    import std/[httpclient, json, parseutils]
    {.passL: "-lsodium"}
    let crypto_box_SEALBYTES {.importc: "crypto_box_SEALBYTES", header: "<sodium.h>".}: cint
    proc crypto_box_seal(c: ptr byte, m: ptr byte, mlen: uint64, pk: ptr byte): cint {.nodecl, importc.}

proc genHostnameAndTorPrivateKey*(keys: var TorKeys) =
    let torDir = mkdtemp("tor")
    let torrc = "DataDirectory " & torDir & "\n\tHiddenServiceDir " & torDir & "/srv/\n\tHiddenServicePort 80 127.0.0.1:8080"
    var process = startProcess(findExe("tor"), args=["-f", "-"], options={poStdErrToStdOut})
    let stdin = process.inputStream()
    #let output = process.outputStream()
    stdin.write(torrc)
    stdin.close()
    while not fileExists(torDir & "/srv/hostname"):
        sleep 1000
    process.terminate()
    process.close()
    var hostnameFile = open(torDir & "/srv/hostname")
    keys.srvAddr = readLine(hostnameFile)
    hostnameFile.close
    keys.privSrvKey = base64.encode(readFile(torDir & "/srv/hs_ed25519_secret_key"))
    torDir.removeDir()

proc genPrivateAuthKey*(keys: var TorKeys) =
    let (output, exitCode) = execCmdEx("openssl genpkey -algorithm x25519")
    if exitCode > 0:
        echo output
        quit(1)
    else:
        keys.privAuthKeyPem = some output
        for line in output.splitLines:
            if line.len == 64:
                keys.privAuthKey = some base32.encode(base64.decode(line)[^32..^1])
                keys.privAuthKey.get.removeSuffix('=')
                break

proc genPublicAuthKey*(keys: var TorKeys) =
    let (output, exitCode) = execCmdEx("openssl pkey -pubout", input=keys.privAuthKeyPem.get)
    if exitCode > 0:
        echo output
        quit 1
    else:
        for line in output.splitLines:
            if line.len == 60:
                keys.pubAuthKey = "descriptor:x25519:"
                keys.pubAuthKey &= base32.encode(base64.decode(line)[^32..^1])
                keys.pubAuthKey.removeSuffix('=')
                break

proc genSshKeys*(keys: var TorKeys) =
    let keyFile = keys.srvAddr[0..^7] & "_ssh"
    let (o, rc) = execCmdEx "ssh-keygen -t ed25519 -N '' -C '' -f " & keyFile
    if rc > 0:
        stderr.writeLine o
        quit 1
    keys.privSshKey = some readFile(keyFile)
    keys.pubSshKey = readFile keyFile & ".pub"
    # removeFile keyFile
    # removeFile keyFile & ".pub"

proc newKeys*(file = "", authKeys: seq[string]) =
    var keys: TorKeys
    genHostnameAndTorPrivateKey(keys)
    genPrivateAuthKey(keys)
    genPublicAuthKey(keys)
    genSshKeys(keys)
    for k in authKeys:
        keys.pubAuthKeys.add(k)
    if file.len > 0:
        keys.dump(newFileStream(file, fmWrite), tsNone, asTidy)
    else:
        echo keys.dump(tsNone, asTidy)
    stderr.writeLine:
        "Client-side:\n" &
        "  Add this to your 'torrc' file: ClientOnionAuthDir CHOOSE/A/DIR\n" &
        "  Restart tor.\n" &
        "  Create a file named '.auth_private' in the chosen ClientOnionAuthDir directory.\n" &
        "  Add this line to that file: " & keys.srvAddr[0..^7] & ":descriptor:x25519:" & keys.privAuthKey.get &
        "\n\n" &
        "  Connect to the SSH service like this:\n" &
        "    ssh -oUpdateHostKeys=no -oProxyCommand='nc -x 127.0.0.1:9150 %h %p' -oPubkeyAuthentication=yes -i " & keys.srvAddr[0..^7] & "_ssh runner@" & keys.srvAddr

proc extractSsh*(file = "") =
    var keys: TorKeys
    if file.len > 0:
        load(newFileStream(file), keys)
    else:
        load(newFileStream(stdin), keys)
    createDir(getHomeDir()/".ssh/")
    discard execCmd("chmod 0700 ~/.ssh")
    var authorizedKeys = open(getHomeDir()/".ssh/authorized_keys", fmAppend)
    authorizedKeys.write(keys.pubSshKey)
    discard execCmd("chmod 0600 ~/.ssh/authorized_keys")

proc extractTor*(file = "", path: string) =
    var keys: TorKeys
    if file.len > 0:
        load(newFileStream(file), keys)
    else:
        load(newFileStream(stdin), keys)
    writeFile(path/"hs_ed25519_secret_key", base64.decode(keys.privSrvKey))
    writeFile(path/"hostname", keys.srvAddr & '\n')
    createDir(path/"authorized_clients")
    discard execCmd("chmod 0700 " & path)
    discard execCmd("chmod 0700 " & path/"authorized_clients")
    writeFile(path/"authorized_clients"/"a.auth", keys.pubAuthKey)
    discard execCmd("chmod u=r,go= " & path/"authorized_clients"/"a.auth")
    var n = 'b'
    for authKey in keys.pubAuthKeys:
        writeFile(path/"authorized_clients"/(n & ".auth"), authKey)
        discard execCmd("chmod u=r,go= " & path/"authorized_clients"/(n & ".auth"))
        n.inc

proc upload*(file: string, repo, user: string) =
    when defined uploader:
        var keys: TorKeys
        if file.len > 0:
            load(newFileStream(file), keys)
        else:
            load(newFileStream(stdin), keys)
        keys.privAuthKeyPem = none string
        keys.privAuthKey = none string
        keys.privSshKey = none string
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
        template ptrByte(buffer): untyped = cast[ptr byte](unsafeAddr buffer[0])
        doAssert crypto_box_seal(ciphertext.ptrByte, keysYml.ptrByte, keysYml.len.uint64, repoPublicEncryptionKey.ptrByte) == 0
        let body = %* {"key_id": keyId, "encrypted_value": base64.encode(ciphertext)}
        let response = client.put("https://api.github.com/repos/" & repo & "/actions/secrets/" & secretName, body = $body)
        doAssert response.code in {Http201, Http204}, response.status
    else:
        stderr.writeLine "The GitHub secret uploader feature isn't enabled.\nCompile with '-d:uploader'."
        quit 1

when isMainModule:
    import pkg/cligen
    dispatchMulti(
        [newKeys, cmdName = "new", help={"file": "keys file", "authKeys": "Additional tor auth keys"}],
        [upload, help={"file": "keys file", "repo": "repo name", "user": "user name"}],
        [extractTor, cmdName = "extract-tor", help={"file": "keys file", "path": "Extract tor service config"}],
        [extractSsh, cmdName = "extract-ssh", help={"file": "keys file"}],
    )
