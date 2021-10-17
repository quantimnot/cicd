import yaml

proc check() =
  discard

proc serve() =
  ## Serve build environment.
  discard

when isMainModule:
  import cligen
  dispatchMulti(
    [check],
    [serve],
  )
