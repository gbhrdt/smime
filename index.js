var util = require('util');
var stream = require('stream');
var spawn = require('child_process').spawn;
var Promise = require('bluebird');

// Expose methods.
exports.sign = sign;

/**
 * Sign a file.
 *
 * @param {object} options Options
 * @param {stream.Readable} options.content Content stream
 * @param {string} options.key Key path
 * @param {string} options.cert Cert path
 * @param {string} [options.password] Key password
 * @param {string} [options.outform] Output format for the PKCS#7 structure (SMIME|PEM|DER)
 * @param {string} [options.nodetach] Use opaque signing or not
 * @param {function} [cb] Optional callback
 * @returns {object} result Result
 * @returns {string} result.output Signed content
 * @returns {ChildProcess} result.child Child process
 */

function sign(options, cb) {
  return new Promise(function (resolve, reject) {
    options = options || {};

    if (!options.content) {
      throw new Error('Invalid content.');
    } else if (!options.key){
      throw new Error('Invalid key.');
    } else if (!options.cert) {
      throw new Error('Invalid certificate.');
    }

    if (typeof options.content === 'string') {
      // http://stackoverflow.com/questions/12755997/how-to-create-streams-from-string-in-node-js
      var s = new stream.Readable();
      s._read = function noop() {};
      s.push(options.content);
      s.push(null);
      options.content = s;
      // s.pipe(process.stdout);
    }

    // openssl smime -sign -signer file.crt -inkey file.pem
    var command = util.format(
      'openssl smime -sign -signer %s -inkey %s -outform %s',
      options.cert,
      options.key,
      options.outform || 'PEM'
    );

    if (options.password) {
      command += util.format(' -passin pass:%s', options.password);
    }
    if (options.nodetach) {
      command += ' -nodetach';
    }
    // console.log(command);

    var args = command.split(' ');
    var child = spawn(args[0], args.splice(1));

    var output = [];

    child.stdout.on('data', function (chunk) {
      output.push(chunk);
    });

    child.on('close', function (code) {
      if (code !== 0)
        reject(new Error('Process failed.'));
      else
        resolve({
          child: child,
          output: Buffer.concat(output)
        });
    });

    options.content.pipe(child.stdin);
  })
  .nodeify(cb);
}
