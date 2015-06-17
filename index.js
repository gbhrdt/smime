var util = require('util');
var spawn = require('child_process').spawn;
var Promise = require('promise');

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

    // openssl smime -sign -signer facturero.crt -inkey facturero.pem -outform PEM -nodetach
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
