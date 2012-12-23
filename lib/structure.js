var fs = require("fs");
var async = require("async");
var db = require("./database");
var pgKeyring = require("..");

function _createStructure(con, queries, callback) {
	async.waterfall([
		async.apply(__getExistingTables, con),
		function(existing, next) {
			var structure = __makeStructure(queries);
			async.forEachSeries(structure, function(it, next) {
				if(existing.indexOf(it.key) != -1)
					return next();

				db.query(con, it.query(con.schema), [ ], next);
			}, next);
		}
	], callback);
}

function __makeStructure(queries) {
	var ret = [ ];

	queries.split(';').forEach(function(it) {
		it = it.replace(/^-+$/mg, "");
		if(it.match(/^\s*$/))
			return;

		var m = it.match(/^\s*([A-Z]+) (TABLE|INDEX|VIEW) "([^"]+)"([\s\S]*)$/i);
		if(!m)
			throw new Error("Unknown query in structure.sql: "+it);

		ret.push({ key: m[3], query: function(schema) {
			if(m[2].toLowerCase() == "index") // No schema for index
				return m[1]+" "+m[2]+" \""+m[3]+"\""+m[4];
			else
				return m[1]+" "+m[2]+" \""+schema+"\".\""+m[3]+"\""+m[4];
		} });
	});

	return ret;
}

function __getExistingTables(con, callback) {
	db.query(con, 'SELECT "table_name" FROM "information_schema"."tables" WHERE "table_schema" = $1 UNION SELECT "indexname" FROM "pg_indexes" WHERE "schemaname" = $1', [ con.schema ], function(err, res) {
		if(err)
			return callback(err);

		var ret = [ ];
		res.rows.forEach(function(it) {
			ret.push(it.table_name);
		});

		callback(null, ret);
	});
}

exports._createStructure = _createStructure;