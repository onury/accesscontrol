/*!
 *  Grunt Configurations
 */
module.exports = function (grunt) {
    'use strict';

    // ----------------------------
    //  GRUNT CONFIG
    // ----------------------------

    let babelFiles = [{
        expand: true,
        cwd: './src',
        src: ['./**/*.js'],
        dest: './build/'
        // ext: '.js'
    }];

    grunt.initConfig({
        // read in the project settings from the `package.json` file into the
        // `pkg` property
        pkg: grunt.file.readJSON('package.json'),

        'clean': {
            options: {
                force: false
            },
            build: [
                './build/**/*'
            ]
        },

        'babel': {
            options: {
                sourceMap: false,
                presets: ['es2015']
            },
            build: {
                options: {
                    retainLines: true
                },
                files: babelFiles
            },
            release: {
                options: {
                    retainLines: false
                },
                files: babelFiles
            }
        },

        'jasmine_nodejs': {
            options: {
                specNameSuffix: 'spec.js',
                helperNameSuffix: 'helper.js',
                useHelpers: false,
                random: false,
                seed: null,
                defaultTimeout: null,
                stopOnFailure: false,
                traceFatal: true,
                reporters: {
                    console: {
                        colors: true,
                        cleanStack: 3,
                        verbosity: 4,
                        listStyle: 'indent',
                        activity: false
                    }
                }
            },
            all: {
                specs: ['./test/**/*.spec.js']
            }
        },

        'docma': {
            traceFatal: true,
            options: {
                config: './docma.config.json'
            }
        }
    });

    // ----------------------------
    //  LOAD GRUNT PLUGINS
    // ----------------------------

    // load grunt plugins
    require('matchdep').filterDev('grunt-*').forEach(grunt.loadNpmTasks);

    // ----------------------------
    //  REGISTER TASKS
    // ----------------------------

    grunt.registerTask('test', ['jasmine_nodejs']);
    grunt.registerTask('build', ['clean:build', 'babel:build', 'test']);
    grunt.registerTask('release', ['clean:build', 'babel:release', 'test', 'docma']);
    grunt.registerTask('default', ['build']);

};
