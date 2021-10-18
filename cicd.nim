import streams
import yaml
from keys import Keys
import secrets

type
  DebugKeys = object
    onionAddr: string
    secOnionKey: string
    pubOnionAuthKeys: seq[string]
    pubSshAuthKeys: seq[string]

proc check() =
  discard

proc serve() =
  ## Serve build environment.
  discard

proc uploadDebugKeys(repo, user: string, file = "") =
  var keys: Keys
  if file.len > 0:
    load(newFileStream(file), keys)
  else:
    load(newFileStream(stdin), keys)
  var debugKeys: DebugKeys
  debugKeys.onionAddr = keys.onionAddr
  debugKeys.secOnionKey = keys.secOnionKey
  debugKeys.pubOnionAuthKeys = keys.pubOnionAuthKeys
  debugKeys.pubSshAuthKeys = keys.pubSshAuthKeys
  repo.putSecret("debug_keys_" & user, debugKeys.dump)

when isMainModule:
  import cligen
  dispatchMulti(
    [check],
    [serve],
    [uploadDebugKeys],
  )
