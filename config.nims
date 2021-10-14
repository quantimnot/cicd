when defined nimscript:
  hint "Processing", off
  hint "GlobalVar", on
  hint "Performance", on
  switch "verbosity", "0"
  switch "styleCheck", "off"
  switch "excessiveStackTrace", "off"

  switch "experimental", "strictEffects"
  switch "experimental", "unicodeOperators"
  switch "experimental", "overloadableEnums"
  switch "define", "nimPreviewDotLikeOps"
  switch "define", "nimPreviewFloatRoundtrip"
  switch "define", "nimStrictDelete"
  switch "gc", "orc"

  switch "define", "ssl"
  switch "define", "withGitHubUploader"
  switch "define", "usesodium"
  switch "define", "release"
  switch "threads", "on"
