module.exports = function (grunt) {
    grunt.loadNpmTasks('grunt-contrib-watch');
    grunt.loadNpmTasks('grunt-browserify');
    grunt.loadNpmTasks('grunt-contrib-uglify');
    grunt.loadNpmTasks('grunt-contrib-clean');
    grunt.loadNpmTasks('grunt-version');

    grunt.registerTask('default', ['version','browserify', 'uglify']);

    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),
        browserify: {
            main: {
                src: 'index-angular.js',
                dest: 'cosignclient-angular.js'
            }
        },
        uglify: {
            main: {
                files: {
                    'cosignclient-angular.min.js': ['cosignclient-angular.js']
                }
            }
        },
        watch: {
            files: 'index-angular.js',
            tasks: ['default']
        },
        clean: ['cosignclient-angular.js', 'cosignclient-angular.min.js'],
        version: {
            bower: {
                src: ['bower.json']
            },
            angular: {
                options: {
                    prefix: "cscModule.constant\\('MODULE_VERSION', '"
                },
                src: ['index-angular.js']
            }
        }
    });
};
