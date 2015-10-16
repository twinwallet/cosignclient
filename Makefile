BIN_PATH:=node_modules/.bin/

all:	cosignclient.min.js

clean:
	rm -f cosignclient.js
	rm -f cosignclient.min.js

cosignclient.js: index.js
	${BIN_PATH}browserify $< > $@

cosignclient.min.js: angular-bitcore-wallet-client.js
	${BIN_PATH}uglify  -s $<  -o $@
