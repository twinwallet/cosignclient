BIN_PATH:=node_modules/.bin/

all:	cosignclient-angular.min.js

clean:
	rm -f cosignclient-angular.js
	rm -f cosignclient-angular.min.js

cosignclient-angular.js: index-angular.js
	${BIN_PATH}browserify $< > $@

cosignclient-angular.min.js: cosignclient-angular.js
	${BIN_PATH}uglify  -s $<  -o $@
