proc installEmscripten() =
    # https://emscripten.org/docs/getting_started/downloads.html
    if not existsEnv "EMSCRIPTEN":
        withDir "deps":
            if dirExists "emsdk":
                withDir "emsdk":
                    direSilentShell "update, install and activate emsdk", "git pull && ./emsdk install latest && ./emsdk activate latest"
            else:
                direSilentShell "clone emsdk repo", "git clone --depth 1 --single-branch https://github.com/emscripten-core/emsdk.git"
                direSilentShell "install and activate emsdk", "cd emsdk && ./emsdk install latest && ./emsdk activate latest"
            putEnv "EMSCRIPTEN", getCurrentDir() / "emsdk/bin/emcc"