# import tor

proc checkruntime() =
  discard
  ## Check the state of `buildserver`'s runtime dependencies.
  # let c = connect_to_controller()
  # discard c.list_onion_services()
  # c.create_onion_service("/var/lib/tor/blah/", 8888.Port, 8888.Port)

proc genkeys(authKeys: seq[string]) =
  ## Generate a new Tor Onion service key and a set of auth keys.
  discard

proc serve(keyfile: string) =
  ## Serve build environment.
  discard

proc build(target: string) =
  ## Build the target.
  discard

when isMainModule:
  import cligen
  dispatchMulti(
    [checkruntime],
    [genkeys, help = {"auth-keys": "additional auth keys"}],
    [serve, help = {"key-file": "path to build server keys"}],
    [build, help = {"build": "build target"}]
  )
