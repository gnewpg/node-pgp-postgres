var pgpTest = require("node-pgp/tests/keyring.js");
var config = require("./config.json");
var pgpPg = require("..");

exports.keyring = function(test) {
	var expect = 2;
	pgpPg.getKeyring(config.db, function(err, keyring) {
		test.ifError(err);

		expect += pgpTest.cdauth.testKeyring(test, keyring, function(err) {
			test.ifError(err);

			test.expect(expect);
			test.done();
		});
	}, true)
};