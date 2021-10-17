proc installAndroidSdk() =
    # https://developer.android.com/studio#downloads
    if not existsEnv "ANDROID_HOME":
        createDir "android_sdk"
        withDir "deps/android_sdk":
            if dirExists "ndk-bundle":
                discard
            else:
                if detectOs(Linux):
                    download "https://dl.google.com/android/repository/commandlinetools-linux-7302050_latest.zip", "commandlinetools.zip"
                    verifySha256 "commandlinetools.zip", "7a00faadc0864f78edd8f4908a629a46d622375cbe2e5814e82934aebecdb622"
                elif detectOs(MacOSX):
                    download "https://dl.google.com/android/repository/commandlinetools-mac-7302050_latest.zip", "commandlinetools.zip"
                    verifySha256 "commandlinetools.zip", "fda8189832e506a58643c119f02c515a5a85741ae9c040fab41ee6c5ac021311"
                elif detectOs(Windows):
                    download "https://dl.google.com/android/repository/commandlinetools-win-7302050_latest.zip", "commandlinetools.zip"
                    verifySha256 "commandlinetools.zip", "868dbb51a07b38c778f3500b1b8b1931221b33348c87c1e461eede9d2a88185f"
                else: raise newException(ValueError, "unsupported build host os")
                unzip "commandlinetools.zip"
                direShell """cmdline-tools/bin/sdkmanager --sdk_root="$PWD" ndk-bundle"""
            putEnv "ANDROID_HOME", getCurrentDir()