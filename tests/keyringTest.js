var pgpTest = require("node-pgp/tests/keyring.js");
var config = require("./config.json");
var pgpPg = require("..");
var db = require("../lib/database");
var ConnectionParameters = require("pg/lib/connection-parameters");

var SCHEMA = "gnewpgtest";

exports.keyring = function(test) {
	var expect = 6;

	db.getConnection(config.db, function(err, con) {
		test.ifError(err);

		con.query('DROP SCHEMA IF EXISTS "'+SCHEMA+'" CASCADE', [ ], function(err) {
			db.query(con, 'CREATE SCHEMA "'+SCHEMA+'"', [ ], function(err) {
				test.ifError(err);

				var dbConfig = new ConnectionParameters(config.db);
				dbConfig.schema = SCHEMA;

				pgpPg.getKeyring(dbConfig, function(err, keyring) {
					test.ifError(err);

					expect += pgpTest.cdauth.testKeyring(test, keyring, function(err) {
						test.ifError(err);

						test.expect(expect);

						keyring.saveChanges(function(err) { // End transaction
							test.ifError(err);

							db.query(con, 'DROP SCHEMA "'+SCHEMA+'" CASCADE', [ ], function(err) {
								test.ifError(err);

								keyring.close();
								con.end();

								test.done();
							});
						});
					});
				}, true)
			});
		});
	})
};