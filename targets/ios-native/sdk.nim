import std/[os]
import pkg/plists

const
  xcodePath {.strdefine.} = "/Applications/Xcode.app"
#   iosSdkPath {.strdefine.} = xcodePath/"Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS" & version & ".sdk"
#   iosSimSdkPath {.strdefine.} = xcodePath/"Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator" & version & ".sdk"

proc install*() =
  discard
