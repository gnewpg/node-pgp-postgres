var pgpTest = require("node-pgp/tests/keyring.js");
var config = require("./config.json");
var pgpPg = require("..");
var db = require("../lib/database");
var pgUtils = require("pg/lib/utils");

var SCHEMA = "gnewpgtest";

exports.keyring = function(test) {
	var expect = 5;

	db.getConnection(config.db, function(err, con) {
		test.ifError(err);

		db.query(con, 'CREATE SCHEMA "'+SCHEMA+'"', [ ], function(err) {
			test.ifError(err);

			var dbConfig = pgUtils.parseConnectionString(config.db);
			dbConfig.schema = SCHEMA;

			pgpPg.getKeyring(dbConfig, function(err, keyring) {
				test.ifError(err);

				expect += pgpTest.cdauth.testKeyring(test, keyring, function(err) {
					test.ifError(err);
					
					test.expect(expect);

					db.query(con, 'DROP SCHEMA "'+SCHEMA+'" CASCADE', [ ], function(err) {
						test.ifError(err);

						test.done();
					});
				});
			}, true)
		})
	})
};