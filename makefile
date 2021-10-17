cicd: cicd.nim secrets.nim keys.nim
	nim c -o:$@ $@.nim

secrets: secrets.nim
	nim c -o:$@ $@.nim

keys: keys.nim
	nim c -o:$@ $@.nim
