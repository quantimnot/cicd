import std/[base64, httpclient, json, os, strutils]

{.passL: "-lsodium"}
let crypto_box_SEALBYTES {.importc: "crypto_box_SEALBYTES", header: "<sodium.h>".}: cint
proc crypto_box_seal(c: ptr byte, m: ptr byte, mlen: uint64, pk: ptr byte): cint {.nodecl, importc.}

template ptrByte(buffer): untyped = cast[ptr byte](unsafeAddr buffer[0])

proc putSecret*(repo, name: string, value = "") =
    block:
      var token = getEnv("GITHUB_TOKEN")
      if token.len == 0:
          stderr.writeLine "error: `GITHUB_TOKEN` environment variable needs set"
          quit 1
      var value = if value.len == 0: stdin.readAll else: value
      var client = newHttpClient()
      client.headers.add("Authorization", "token " & token)
      client.headers.add("Accept", "application/vnd.github.v3+json")
      var repoPublicEncryptionKey = client.getContent("https://api.github.com/repos/" & repo & "/actions/secrets/public-key")
      let keyId = repoPublicEncryptionKey.parseJson()["key_id"].getStr
      repoPublicEncryptionKey = base64.decode(repoPublicEncryptionKey.parseJson()["key"].getStr)
      var ciphertext = newString(crypto_box_SEALBYTES + value.len)
      doAssert crypto_box_seal(ciphertext.ptrByte, value.ptrByte, value.len.uint64, repoPublicEncryptionKey.ptrByte) == 0
      let body = %* {"key_id": keyId, "encrypted_value": base64.encode(ciphertext)}
      let response = client.put("https://api.github.com/repos/" & repo & "/actions/secrets/" & name, body = $body)
      doAssert response.code in {Http201, Http204}, response.status

when isMainModule:
    import pkg/cligen
    dispatch(putSecret)
