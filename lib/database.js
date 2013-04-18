var pg = require("pg");
var pgUtils = require("pg/lib/utils");
var pgQuery = require("pg/lib/query");
var pgp = require("node-pgp");


// Fix writing of binary fields into the database
var origPrepareValue = pgUtils.prepareValue;
pgUtils.prepareValue = function(val) {
	if(val instanceof Buffer) // For binary fields until https://github.com/brianc/node-postgres/pull/92 is fixed
	{
		var esc = "";
		for(var i=0; i<val.length; i++)
		{
			var char = val.readUInt8(i).toString(8);
			if(char.length == 1)
				esc += "\\00"+char;
			else if(char.length == 2)
				esc += "\\0"+char;
			else
				esc += "\\"+char;
		}
		return esc;
	}

	return origPrepareValue.apply(pgUtils, arguments);
};


// Print SQL errors to stderr
var origHandleError = pgQuery.prototype.handleError;
pgQuery.prototype.handleError = function(err) {
	console.warn("SQL error", err, this);

	return origHandleError.apply(this, arguments);
};

function getConnection(config, callback) {
	var schema = config.schema || "public";

	pg.connect(config, function(err, con, done) {
		if(err)
			return callback(err);

		con.done = done;

		query(con, 'SET search_path = "'+schema+'"', [ ], function(err) {
			if(err)
				return callback(err);

			con.schema = schema;

			callback(null, con);
		});
	});
}

function query(con, query, args, callback) {
	con.query(query, args, callback);
}

function query1(con, queryStr, args, callback) {
	query(con, queryStr, args, function(err, res) {
		if(err)
			callback(err);
		else if(res.rowCount < 1)
			callback(null, null);
		else
			callback(null, res.rows[0]);
	});
}

function fifoQuery(con, query, args) {
	var queryObj = con.query(query, args);
	var ret = new pgp.Fifo();

	queryObj.on("row", function(row) {
		ret._add(row);
	});

	queryObj.on("error", function(err) {
		ret._end(err);
	});

	queryObj.on("end", function() {
		ret._end();
	});

	return ret;
}

function _getEntries(table, fields, filter, suffix) {
	var args = [ ];
	var q = 'SELECT ';
	if(Array.isArray(fields))
	{
		if(fields.length == 0)
			q += "''";
		else
			q += '"'+fields.join('", "')+'"';
	}
	else
		q += fields;
	q += ' FROM "'+table+'"';

	var filter = _filterToCondition(filter, args);
	if(filter)
		q += ' WHERE '+filter;

	if(suffix)
		q += ' '+suffix;

	return { query: q, args: args };
}

function getEntries(con, table, fields, filter, suffix) {
	var q = _getEntries(table, fields, filter, suffix);
	return fifoQuery(con, q.query, q.args);
}

function getEntriesAtOnce(con, table, fields, filter, suffix, callback) {
	if(typeof suffix == "function")
	{
		callback = suffix;
		suffix = null;
	}

	var q = _getEntries(table, fields, filter, suffix);
	query(con, q.query, q.args, function(err, res) {
		if(err)
			callback(err);
		else
			callback(null, res.rows)
	});
}

function getEntry(con, table, fields, filter, callback) {
	var q = _getEntries(table, fields, filter, "LIMIT 1");
	query1(con, q.query, q.args, callback);
}

function entryExists(con, table, filter, callback) {
	var q = _getEntries(table, "COUNT(*) AS n", filter, "LIMIT 1");
	query1(con, q.query, q.args, function(err, res) {
		if(err)
			callback(err);
		else
			callback(null, res.n > 0);
	});
}

function update(con, table, fields, filter, callback) {
	var args = [ ];
	var q = 'UPDATE "'+table+'" SET ';

	var n = 1;
	for(var i in fields)
	{
		if(n > 1)
			q += ', ';
		q += '"'+i+'" = $'+(n++);
		args.push(fields[i]);
	}

	var filter = _filterToCondition(filter, args);
	q += ' WHERE '+filter;

	query(con, q, args, callback);
}

function insert(con, table, fields, callback) {
	var args = [ ];
	var q = 'INSERT INTO "'+table+'" ( ';
	var q2 = '';

	var n = 1;
	for(var i in fields)
	{
		if(n > 1)
		{
			q += ', ';
			q2 += ', ';
		}
		q += '"'+i+'"';
		q2 += '$'+(n++);
		args.push(fields[i]);
	}

	q += ' ) VALUES ( '+q2+' )';

	query(con, q, args, callback);
}

function insertIfNotExists(con, table, fields, idFields, callback) {
	if(typeof idFields == "function") {
		callback = idFields;
		idFields = null;
	}

	var existsFilter = { };
	if(idFields) {
		for(var i=0; i<idFields.length; i++)
			existsFilter = fields[idFields[i]];
	}
	else
		existsFilter = fields;

	entryExists(con, table, existsFilter, function(err, exists) {
		if(err || exists)
			return callback(err);

		insert(con, table, fields, callback);
	});
}

function remove(con, table, filter, callback) {
	var args = [ ];
	var q = 'DELETE FROM "'+table+'"';

	var filter = _filterToCondition(filter, args);
	if(filter)
		q += ' WHERE '+filter;

	query(con, q, args, callback);
}

function _filterToCondition(filter, args) {
	if(!filter)
		return null;

	var ret = [ ];
	for(var i in filter)
		ret.push(pgp.Keyring.Filter.get(filter[i]).toPostgresCondition(i, args));

	return ret.length > 0 ? ret.join(" AND ") : null;
}

exports.getConnection = getConnection;
exports.query = query;
exports.query1 = query1;
exports.fifoQuery = fifoQuery;
exports.getEntries = getEntries;
exports.getEntriesAtOnce = getEntriesAtOnce;
exports.getEntry = getEntry;
exports.entryExists = entryExists;
exports.update = update;
exports.insert = insert;
exports.insertIfNotExists = insertIfNotExists;
exports.remove = remove;
exports.delete = remove;