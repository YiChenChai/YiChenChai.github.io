'use strict';

var gulp          = require('gulp');
var gutil         = require('gulp-util');

var cryptojs      = require('crypto-js');
var marked        = require('marked');
var FileSystem    = require('fs');
var Path          = require('path');
var through       = require('through2');
var childProcess = require("child_process");

var PluginError   = gutil.PluginError;

/*
  START FIREWALL TASKS
*/
function checkEncryptedLayout(frontMatter, filepath) {
  var lines = frontMatter.split('\n'),
      linesWithoutLayout = [],
      hasEncryptedLayout = false;

  lines.forEach(function(line) {
    var layoutTag = 'layout:',
        isLayoutIndex = line.indexOf(layoutTag),
        isLayout = isLayoutIndex >= 0,
        isEncryptedLayout = line.indexOf('encrypted') >= (isLayoutIndex + layoutTag.length);

    if (isLayout) {
      // in case of multiple instances of layout
      hasEncryptedLayout = isEncryptedLayout ? true : false;
    }
  });

  if (!hasEncryptedLayout) {
    console.log('[WARNING] ' + filepath + ': protected file not using encrypted layout.');
  }

  // var linesWithLayout = linesWithoutLayout
  //   .splice(0, 1)
  //   .concat('layout: encrypted')
  //   .concat(linesWithoutLayout);

  // var frontMatterWithEncryptedLayout = linesWithLayout.join('\n');
  // return frontMatterWithEncryptedLayout;
}

function encrypt(password) {
  return through.obj(function(file, encoding, callback) {
    if (file.isNull() || file.isDirectory()) {
      this.push(file);
      return callback();
    }

    // No support for streams
    if (file.isStream()) {
      this.emit('error', new PluginError({
        plugin: 'Encrypt',
        message: 'Streams are not supported.'
      }));
      return callback();
    }

    if (file.isBuffer()) {
      var delimiter = '---',
          frontMatter = String(file.contents).split(delimiter)[1],
          settings = frontMatter.split('\n');
      // console.log(settings);
      for (let i = 0; i < settings.length; i++) {
          var settingname = settings[i].split(':')[0];
          // console.log(settingname);
          if (settingname == 'password') {
		var passw = settings[i].split(':')[1].trimLeft();
		password = passw;
		frontMatter = frontMatter.replace(settings[i], '');
          }
      }
      var pathSects = Path.basename(file.path).split('.');
      var targetPath = '/tmp/code/' + pathSects.slice(0, pathSects.length - 1).join('.') + '.html';
      var encryptedBody = cryptojs.AES.encrypt(FileSystem.readFileSync(targetPath).toString(), password),
          hmac = cryptojs.HmacSHA256(encryptedBody.toString(), cryptojs.SHA256(password).toString()).toString(),
          encryptedFrontMatter = 'encrypted: ' + hmac + encryptedBody,
          result = [ delimiter, frontMatter, '\n', 'layout: encrypted', '\n', encryptedFrontMatter, '\n', delimiter ];

      file.contents = new Buffer(result.join(''));
      this.push(file);
      return callback();
    }
  });
}

gulp.task('firewall:encrypt', () => {
  childProcess.execSync('jekyll build --config _config.yml -s _protected -d /tmp/code', (a,b,c)=>{});
  var res = gulp.src('_protected/*.*')
    .pipe(encrypt('password'))
    .pipe(gulp.dest('_posts'));
  // childProcess.execSync('rm -rf /tmp/code', (a,b,c)=>{});
  return res;
});


gulp.task('firewall', gulp.series(['firewall:encrypt'], () => {}));

/*
  END FIREWALL TASKS
*/

gulp.task('default', gulp.series(['firewall'], () => {
  // your tasks here
}));
