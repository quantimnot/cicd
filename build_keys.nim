import std/[base64, osproc, posix_utils, streams, os, parseopt, strutils, sequtils]
import
    pkg/[
        yaml,
        base32,
    ]

const torHiddenServiceKeyFilename = "hs_ed25519_secret_key"

type
    TorKeys* = object
        srvAddr: string
        privSrvKey: string
        privAuthKeyPem {.transient.}: string
        privAuthKey {.transient.}: string
        pubSshKey: string
        pubAuthKey: string
        pubAuthKeys: seq[string]

when defined withGitHubUploader:
    import std/[httpclient, json, parseutils]
    {.passL: "-lsodium"}
    let crypto_box_SEALBYTES {.importc: "crypto_box_SEALBYTES", header: "<sodium.h>".}: cint
    proc crypto_box_seal(c: ptr byte, m: ptr byte, mlen: uint64, pk: ptr byte): cint {.nodecl, importc.}

proc genHostnameAndTorPrivateKey*(): (string, string) =
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
    result[0] = readLine(hostnameFile)
    hostnameFile.close
    result[1] = readFile(torDir & "/srv/" & torHiddenServiceKeyFilename)
    torDir.removeDir()

proc genPrivateAuthKey*(): (string, string) =
    let (output, exitCode) = execCmdEx("openssl genpkey -algorithm x25519")
    if exitCode > 0:
        echo output
    else:
        result[0] = output
        var thisLineIsIt = false
        for line in output.splitLines:
            if thisLineIsIt:
                result[1] = base32.encode(base64.decode(line)[32..^1])
                result[1].removeSuffix('=')
                break
            if line == "-----BEGIN PRIVATE KEY-----":
                thisLineIsIt = true

proc genPublicAuthKey*(pemEncodedPrivateKey: string): string =
    let (output, exitCode) = execCmdEx("openssl pkey -pubout", input=pemEncodedPrivateKey)
    if exitCode > 0:
        echo output
    else:
        var thisLineIsIt = false
        for line in output.splitLines:
            if thisLineIsIt:
                result = "descriptor:x25519:"
                result &= base32.encode(base64.decode(line)[32..^1])
                result.removeSuffix('=')
                break
            if line == "-----BEGIN PUBLIC KEY-----":
                thisLineIsIt = true

proc genSshKeys*(keys: var TorKeys) =
    if not fileExists("runner.pub"):
        discard execCmd("ssh-keygen -t ed25519 -p '' -f runner")
    keys.pubSshKey = readFile("runner.pub")

proc newBuildKeys*(additionalAuthKeys: seq[string]): TorKeys =
    var keys: TorKeys
    keys.genSshKeys
    let (hostname, servicePrivateKey) = genHostnameAndTorPrivateKey()
    keys.srvAddr = hostname
    keys.privSrvKey = base64.encode(servicePrivateKey)
    let (pemEncodedPrivateAuthKey, privateAuthKey) = genPrivateAuthKey()
    keys.privAuthKeyPem = pemEncodedPrivateAuthKey
    keys.privAuthKey = privateAuthKey
    keys.pubAuthKey = genPublicAuthKey(pemEncodedPrivateAuthKey)
    for k in additionalAuthKeys:
        keys.pubAuthKeys.add(k)
    keys

proc extractKeys*(path: string, file = stdin) =
    var keys: TorKeys
    load(newFileStream(stdin), keys)
    writeFile(path/torHiddenServiceKeyFilename, base64.decode(keys.privSrvKey))
    writeFile(path/"hostname", keys.srvAddr & '\n')
    createDir(path/"authorized_clients")
    writeFile(path/"authorized_clients"/"0.auth", keys.pubAuthKey)
    var n = 1
    for authKey in keys.pubAuthKeys:
        writeFile(path/"authorized_clients"/($n & ".auth"), authKey)
        n.inc
    
    # SSH
    createDir("~/.ssh/")
    discard execCmd("chmod 0700 ~/.ssh")
    writeFile("~/.ssh/id_ed25519.pub", keys.pubSshKey)
    discard execCmd("chmod u=r,go= ~/.ssh/id_ed25519.pub")

when defined withGitHubUploader:
    proc uploadToGitHubRepoSecrets*(repo, user: string, keys: string) =
        doAssert existsEnv("GITHUB_TOKEN"), "`GITHUB_TOKEN` environment variable needs set"
        var client = newHttpClient()
        var secretName = "debug_keys_" & user
        client.headers.add("Authorization", "token " & getEnv("GITHUB_TOKEN"))
        client.headers.add("Accept", "application/vnd.github.v3+json")
        var repoPublicEncryptionKey = client.getContent("https://api.github.com/repos/" & repo & "/actions/secrets/public-key")
        let keyId = repoPublicEncryptionKey.parseJson()["key_id"].getStr
        repoPublicEncryptionKey = base64.decode(repoPublicEncryptionKey.parseJson()["key"].getStr)
        var ciphertext = newString(crypto_box_SEALBYTES + keys.len)
        template ptrByte(buffer): untyped = cast[ptr byte](unsafeAddr buffer[0])
        doAssert crypto_box_seal(ciphertext.ptrByte, keys.ptrByte, keys.len.uint64, repoPublicEncryptionKey.ptrByte) == 0
        let body = %* {"key_id": keyId, "encrypted_value": base64.encode(ciphertext)}
        let response = client.put("https://api.github.com/repos/" & repo & "/actions/secrets/" & secretName, body = $body)
        doAssert response.code in {Http201, Http204}, response.status

when isMainModule:
    proc usage =
        echo "Writes to stdout:\n\ttor_onion_hostname\n\tprivate_auth_key\n\ttor_private_key\n\ttor_public_auth_key\n\t[additional tor_public_auth_key]"
        echo "--add-auth-keys:publicAuthKey0,publicAuthKey1,..."
        echo "\tAdd additional auth keys to the build keys."
        echo "--extract-to:path"
        echo "\tReads build keys from stdin and extracts them to given path."
        when defined withGitHubUploader:
          echo "GitHub options:"
          echo "\tUploads keys to GitHub instead of stdout."
          echo "\t--repo:owner/repo"
          echo "\t--user:username"
          echo "\t\tOptional; will use repo owner username if not given."

    proc invalidOption(key: string) =
        echo "Error: Invalid option: " & key
        usage()
        quit(1)

    proc parseGitHubUploaderOpts(key, val: string, repo, user: var string) =
        case key
        of "repo":
            repo = val
        of "user":
            user = val
        else: invalidOption(key)
        if repo.len > 0 and user.len == 0:
            discard parseUntil(repo, user, '/')

    proc main() =
        var additionalAuthKeys: seq[string]
        var extractionPath: string
        when defined withGitHubUploader:
            var repo, user: string
        for kind, key, val in getopt():
            case kind
            of cmdLongOption, cmdShortOption:
                case key
                of "h", "help":
                    usage()
                    quit(0)
                of "extract-to":
                    doAssert dirExists(val), "extraction path does not exist"
                    extractionPath = val
                of "add-auth-keys":
                    additionalAuthKeys = split(val, {','}).toSeq
                else:
                    when defined withGitHubUploader:
                        parseGitHubUploaderOpts(key, val, repo, user)
                    else:
                        invalidOption(key)
            else: discard
        if extractionPath.len > 0:
            extractKeys(extractionPath)
        else:
            let keys = newBuildKeys(additionalAuthKeys).dump(tsNone, asTidy)
            stdout.write(keys)
            if repo.len > 0 and user.len > 0:
                when defined withGitHubUploader:
                    uploadToGitHubRepoSecrets(repo, user, keys)
                else:
                    discard
    main()
