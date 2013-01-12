var db = require("./database");
var pgp = require("node-pgp");
var util = require("util");
var async = require("async");
var fs = require("fs");
var structure = require("./structure");
var filters = require("./filters"); // This must be included to override the filters

var tableFields = { };
tableFields.keys = [ "id", "fingerprint", "binary", "date", "expires", "revoked", "security" ];
tableFields.keys_subkeys = [ "parentkey", "id", "fingerprint", "binary", "security", "date", "expires", "revoked", "security" ];
tableFields.keys_identities = [ "key", "id", "name", "email" ];
tableFields.keys_identities_selfsigned = [ "key", "id", "name", "email", "expires", "revoked" ];
tableFields.keys_attributes = [ "key", "id", "binary" ];
tableFields.keys_attributes_selfsigned = [ "key", "id", "binary", "expires", "revoked" ];
tableFields.keys_signatures = [ "key", "id", "issuer", "date", "binary", "verified", "sigtype", "expires", "revoked", "security" ];
tableFields.keys_identities_signatures = [ "key", "identity", "id", "issuer", "date", "binary", "verified", "sigtype", "expires", "revoked", "security" ];
tableFields.keys_attributes_signatures = [ "key", "attribute", "id", "issuer", "date", "binary", "verified", "sigtype", "expires", "revoked", "security" ];

var KEY_SIGTYPES = [ pgp.consts.SIG.KEY, pgp.consts.SIG.KEY_REVOK, pgp.consts.SIG.KEY_BY_SUBKEY ];
var SUBKEY_SIGTYPES = [ pgp.consts.SIG.SUBKEY, pgp.consts.SIG.SUBKEY_REVOK ];

function getKeyring(dbConfig, callback, initialise) {
	var con;

	async.waterfall([
		function(next) {
			db.getConnection(dbConfig, function(err, con) {
				next(err, con); // Somehow passing next as callback directly does not work
			});
		},
		function(c, next) {
			con = c;

			if(initialise)
				initialiseDatabase(dbConfig, next);
			else
				next();
		},
		function(next) {
			next(null, new _KeyringPostgres(con));
		}
	], callback);
}

function initialiseDatabase(dbConfig, callback) {
	fs.readFile(__dirname+"/structure.sql", "utf8", function(err, queries) {
		if(err)
			return callback(err);

		db.getConnection(dbConfig, function(err, con) {
			if(err)
				return callback(err);

			structure._createStructure(con, queries, callback);
		});
	});
}

function _KeyringPostgres(con) {
	this._con = con;
}

util.inherits(_KeyringPostgres, pgp.Keyring);

pgp.utils.extend(_KeyringPostgres.prototype, {
	getKeyList : function(filter) {
		return _getList(this._con, "keys", "id", filter, pgp.packetContent.getPublicKeyPacketInfo);
	},

	getKeys : function(filter, fields) {
		return _getEntries(this._con, "keys", filter, fields, pgp.packetContent.getPublicKeyPacketInfo);
	},

	keyExists : function(id, callback) {
		_exists(this._con, "keys", { id: id }, pgp.packetContent.getPublicKeyPacketInfo, callback);
	},

	getKey : function(id, callback, fields) {
		_getEntry(this._con, "keys", { id: id }, fields, pgp.packetContent.getPublicKeyPacketInfo, callback);
	},

	_addKey : function(keyInfo, callback) {
		_addEntry(this._con, "keys", keyInfo, callback);
	},

	_updateKey : function(id, fields, callback) {
		_updateEntry(this._con, "keys", fields, { id: id }, [ "id" ], pgp.packetContent.getPublicKeyPacketInfo, callback);
	},

	_removeKey : function(id, callback) {
		_isSubkey(this._con, id, function(err, is) {
			if(err || is)
				callback(err);
			else
				_removeEntry(this._con, "keys", { id: id }, [ "id" ], pgp.packetContent.getPublicKeyPacketInfo, callback);
		});
	},

	getSubkeyList : function(keyId, filter) {
		return _getList(this._con, "keys_subkeys", "id", pgp.utils.extend({ parentkey: keyId }, filter), pgp.packetContent.getPublicSubkeyPacketInfo);
	},

	getSubkeys : function(keyId, filter, fields) {
		return _getEntries(this._con, "keys_subkeys", pgp.utils.extend({ parentkey: keyId }, filter), fields, pgp.packetContent.getPublicSubkeyPacketInfo);
	},

	subkeyExists : function(keyId, id, callback) {
		_exists(this._con, "keys_subkeys", { parentkey: keyId, id: id }, pgp.packetContent.getPublicSubkeyPacketInfo, callback);
	},

	getSubkey : function(keyId, id, callback, fields) {
		_getEntry(this._con, "keys_subkeys", { parentkey: keyId, id: id }, fields, pgp.packetContent.getPublicSubkeyPacketInfo, callback);
	},

	getSelfSignedSubkeys : function(keyId, filter, fields) {
		return this.getSubkeys(keyId, filter, fields);
	},

	getSelfSignedSubkey : function(keyId, id, callback, fields) {
		this.getSubkey(keyId, id, callback, fields);
	},

	_addSubkey : function(keyId, subkeyInfo, callback) {
		this._addKey(subkeyInfo, callback);
	},

	_updateSubkey : function(keyId, subkeyId, fields, callback) {
		this._updateKey(subkeyId, fields, callback);
	},

	_removeSubkey : function(keyId, subkeyId, callback) {
		_isMainKey(this._con, keyId, subkeyId, function(err, is) {
			if(err || is)
				callback(err);
			else
				_removeEntry(this._con, "keys", { id: subkeyId }, [ "id" ], pgp.packetContent.getPublicKeyPacketInfo, callback);
		});
	},

	getParentKeyList : function(subkeyId) {
		return _getList(this._con, "keys_subkeys", "parentkey", { id: subkeyId }, pgp.packetContent.getPublicSubkeyPacketInfo);
	},

	getIdentityList : function(keyId, filter) {
		return _getList(this._con, "keys_identities", "id", pgp.utils.extend({ key: keyId }, filter), pgp.packetContent.getIdentityPacketInfo);
	},

	getIdentities : function(keyId, filter, fields) {
		return _getEntries(this._con, "keys_identities", pgp.utils.extend({ key: keyId }, filter), fields, pgp.packetContent.getIdentityPacketInfo);
	},

	identityExists : function(keyId, id, callback) {
		_exists(this._con, "keys_identities", { key: keyId, id: id }, pgp.packetContent.getIdentityPacketInfo, callback);
	},

	getIdentity : function(keyId, id, callback, fields) {
		_getEntry(this._con, "keys_identities", { key: keyId, id: id }, fields, pgp.packetContent.getIdentityPacketInfo, callback);
	},

	getSelfSignedIdentities : function(keyId, filter, fields) {
		return _getEntries(this._con, "keys_identities_selfsigned", pgp.utils.extend({ key: keyId }, filter), fields, pgp.packetContent.getIdentityPacketInfo);
	},

	getSelfSignedIdentity : function(keyId, id, callback, fields) {
		_getEntry(this._con, "keys_identities_selfsigned", { key: keyId, id: id }, fields, pgp.packetContent.getIdentityPacketInfo, callback);
	},

	_addIdentity : function(keyId, identityInfo, callback) {
		_addEntry(this._con, "keys_identities", pgp.utils.extend({ }, identityInfo, { key: keyId }), callback);
	},

	_updateIdentity : function(keyId, identityId, fields, callback) {
		_updateEntry(this._con, "keys_identities", fields, { key: keyId, id: identityId }, [ "key", "id" ], pgp.packetContent.getIdentityPacketInfo, callback);
	},

	_removeIdentity : function(keyId, id, callback) {
		_removeEntry(this._con, "keys_identities", { key: keyId, id: id }, [ "key", "id" ], pgp.packetContent.getIdentityPacketInfo, callback);
	},

	getAttributeList : function(keyId, filter) {
		return _getList(this._con, "keys_attributes", "id", pgp.utils.extend({ key: keyId }, filter), pgp.packetContent.getAttributePacketInfo);
	},

	getAttributes : function(keyId, filter, fields) {
		return _getEntries(this._con, "keys_attributes", pgp.utils.extend({ key: keyId }, filter), fields, pgp.packetContent.getAttributePacketInfo);
	},

	attributeExists : function(keyId, id, callback) {
		_exists(this._con, "keys_attributes", { key: keyId, id: id }, pgp.packetContent.getAttributePacketInfo, callback);
	},

	getAttribute : function(keyId, id, callback, fields) {
		_getEntry(this._con, "keys_attributes", { key: keyId, id: id }, fields, pgp.packetContent.getAttributePacketInfo, callback);
	},

	getSelfSignedAttributes : function(keyId, filter, fields) {
		return _getEntries(this._con, "keys_attributes_selfsigned", pgp.utils.extend({ key: keyId }, filter), fields, pgp.packetContent.getAttributePacketInfo);
	},

	getSelfSignedAttribute : function(keyId, id, callback, fields) {
		_getEntry(this._con, "keys_attributes_selfsigned", { key: keyId, id: id }, fields, pgp.packetContent.getAttributePacketInfo, callback);
	},

	_addAttribute : function(keyId, attributeInfo, callback) {
		_addEntry(this._con, "keys_attributes", pgp.utils.extend({ }, attributeInfo, { key: keyId }), callback);
	},

	_updateAttribute : function(keyId, attributeId, fields, callback) {
		_updateEntry(this._con, "keys_attributes", fields, { key: keyId, id: attributeId }, [ "key", "id" ], pgp.packetContent.getAttributePacketInfo, callback);
	},

	_removeAttribute : function(keyId, id, callback) {
		_removeEntry(this._con, "keys_attributes", { key: keyId, id: id }, [ "key", "id" ], pgp.packetContent.getAttributePacketInfo, callback);
	},

	getKeySignatureList : function(keyId, filter) {
		return _getList(this._con, "keys_signatures", "id", pgp.utils.extend({ key: keyId, sigtype: KEY_SIGTYPES }, filter), pgp.packetContent.getSignaturePacketInfo);
	},

	getKeySignatures : function(keyId, filter, fields) {
		return _getEntries(this._con, "keys_signatures", pgp.utils.extend({ key: keyId, sigtype: KEY_SIGTYPES }, filter), fields, pgp.packetContent.getSignaturePacketInfo);
	},

	getKeySignatureListByIssuer : function(issuerId, filter) {
		filter = pgp.utils.extend({ issuer: issuerId, sigtype: KEY_SIGTYPES }, filter);
		return pgp.Fifo.map(_getEntries(this._con, "keys_signatures", filter, [ "key", "id" ], pgp.packetContent.getSignaturePacketInfo), function(signatureRecord, callback) {
			callback(null, { keyId: signatureRecord.key, signatureId: signatureRecord.id });
		});
	},

	keySignatureExists : function(keyId, id, callback) {
		_exists(this._con, "keys_signatures", { key: keyId, id: id, sigtype: KEY_SIGTYPES }, pgp.packetContent.getSignaturePacketInfo, callback);
	},

	getKeySignature : function(keyId, id, callback, fields) {
		_getEntry(this._con, "keys_signatures", { key: keyId, id: id, sigtype: KEY_SIGTYPES }, fields, pgp.packetContent.getSignaturePacketInfo, callback);
	},

	_addKeySignature : function(keyId, signatureInfo, callback) {
		_addEntry(this._con, "keys_signatures", pgp.utils.extend({ }, signatureInfo, { key: keyId }), callback);
	},

	_updateKeySignature : function(keyId, signatureId, fields, callback) {
		_updateEntry(this._con, "keys_signatures", fields, { key: keyId, id: signatureId }, [ "key", "id" ], pgp.packetContent.getSignaturePacketInfo, callback);
	},

	_removeKeySignature : function(keyId, id, callback) {
		_removeEntry(this._con, "keys_signatures", { key: keyId, id: id }, [ "key", "id" ], pgp.packetContent.getSignaturePacketInfo, callback);
	},

	getSubkeySignatureList : function(keyId, subkeyId, filter) {
		return _getList(this._con, "keys_signatures", "id", pgp.utils.extend({ key: subkeyId, sigtype: SUBKEY_SIGTYPES, issuer: keyId }, filter), pgp.packetContent.getSignaturePacketInfo);
	},

	getSubkeySignatures : function(keyId, subkeyId, filter, fields) {
		return _getEntries(this._con, "keys_signatures", pgp.utils.extend({ key: subkeyId, sigtype: SUBKEY_SIGTYPES, issuer: keyId }, filter), fields, pgp.packetContent.getSignaturePacketInfo);
	},

	getSubkeySignatureListByIssuer : function(issuerId, filter) {
		filter = pgp.utils.extend({ issuer: issuerId, sigtype: SUBKEY_SIGTYPES }, filter);
		return pgp.Fifo.map(_getEntries(this._con, "keys_signatures", filter, [ "key", "id" ], pgp.packetContent.getSignaturePacketInfo), function(signatureRecord, callback) {
			callback(null, { keyId: issuerId, subkeyId: signatureRecord.key, signatureId: signatureRecord.id });
		});
	},

	subkeySignatureExists : function(keyId, subkeyId, id, callback) {
		_exists(this._con, "keys_signatures", { key: subkeyId, issuer: keyId, id: id, sigtype: SUBKEY_SIGTYPES }, pgp.packetContent.getSignaturePacketInfo, callback);
	},

	getSubkeySignature : function(keyId, subkeyId, id, callback, fields) {
		_getEntry(this._con, "keys_signatures", { key: keyId, id: id, sigtype: SUBKEY_SIGTYPES }, fields, pgp.packetContent.getSignaturePacketInfo, callback);
	},

	_addSubkeySignature : function(keyId, subkeyId, signatureInfo, callback) {
		this._addKeySignature(subkeyId, signatureInfo, callback);
	},

	_updateSubkeySignature : function(keyId, subkeyId, signatureId, fields, callback) {
		this._updateKeySignature(subkeyId, signatureId, fields, callback);
	},

	_removeSubkeySignature : function(keyId, subkeyId, id, callback) {
		this._removeKeySignature(subkeyId, id, callback);
	},

	getIdentitySignatureList : function(keyId, identityId, filter) {
		return _getList(this._con, "keys_identities_signatures", "id", pgp.utils.extend({ key: keyId, identity: identityId }, filter), pgp.packetContent.getSignaturePacketInfo);
	},

	getIdentitySignatures : function(keyId, identityId, filter, fields) {
		return _getEntries(this._con, "keys_identities_signatures", pgp.utils.extend({ key: keyId, identity: identityId }, filter), fields, pgp.packetContent.getSignaturePacketInfo);
	},

	getIdentitySignatureListByIssuer : function(issuerId, filter) {
		return pgp.Fifo.map(_getEntries(this._con, "keys_identities_signatures", pgp.utils.extend({ issuer: issuerId }, filter), [ "key", "identity", "id" ], pgp.packetContent.getSignaturePacketInfo), function(signatureRecord, callback) {
			callback(null, { keyId: signatureRecord.key, identityId: signatureRecord.identity, signatureId: signatureRecord.id });
		});
	},

	identitySignatureExists : function(keyId, identityId, id, callback) {
		_exists(this._con, "keys_identities_signatures", { key: keyId, identity: identityId, id: id }, pgp.packetContent.getSignaturePacketInfo, callback);
	},

	getIdentitySignature : function(keyId, identityId, id, callback, fields) {
		_getEntry(this._con, "keys_identities_signatures", { key: keyId, identity: identityId, id: id }, fields, pgp.packetContent.getSignaturePacketInfo, callback);
	},

	_addIdentitySignature : function(keyId, identityId, signatureInfo, callback) {
		_addEntry(this._con, "keys_identities_signatures", pgp.utils.extend({ }, signatureInfo, { key: keyId, identity: identityId }), callback);
	},

	_updateIdentitySignature : function(keyId, identityId, signatureId, fields, callback) {
		_updateEntry(this._con, "keys_identities_signatures", fields, { key: keyId, identity: identityId, id: signatureId }, [ "key", "identity", "id" ], pgp.packetContent.getSignaturePacketInfo, callback);
	},

	_removeIdentitySignature : function(keyId, identityId, id, callback) {
		_removeEntry(this._con, "keys_identities_signatures", { key: keyId, identity: identityId, id: id }, [ "key", "identity", "id" ], pgp.packetContent.getSignaturePacketInfo, callback);
	},

	getAttributeSignatureList : function(keyId, attributeId, filter) {
		return _getList(this._con, "keys_attributes_signatures", "id", pgp.utils.extend({ key: keyId, attribute: attributeId }, filter), pgp.packetContent.getSignaturePacketInfo);
	},

	getAttributeSignatures : function(keyId, attributeId, filter, fields) {
		return _getEntries(this._con, "keys_attributes_signatures", pgp.utils.extend({ key: keyId, attribute: attributeId }, filter), fields, pgp.packetContent.getSignaturePacketInfo);
	},

	getAttributeSignatureListByIssuer : function(issuerId, filter) {
		return pgp.Fifo.map(_getEntries(this._con, "keys_attributes_signatures", pgp.utils.extend({ issuer: issuerId }, filter), [ "key", "attribute", "id" ], pgp.packetContent.getSignaturePacketInfo), function(signatureRecord, callback) {
			callback(null, { keyId: signatureRecord.key, attributeId: signatureRecord.attribute, signatureId: signatureRecord.id });
		});
	},

	attributeSignatureExists : function(keyId, attributeId, id, callback) {
		_exists(this._con, "keys_attributes_signatures", { key: keyId, attribute: attributeId, id: id }, pgp.packetContent.getSignaturePacketInfo, callback);
	},

	getAttributeSignature : function(keyId, attributeId, id, callback, fields) {
		_getEntry(this._con, "keys_attributes_signatures", { key: keyId, attribute: attributeId, id: id }, fields, pgp.packetContent.getSignaturePacketInfo, callback);
	},

	_addAttributeSignature : function(keyId, attributeId, signatureInfo, callback) {
		_addEntry(this._con, "keys_attributes_signatures", pgp.utils.extend({ }, signatureInfo, { key: keyId, attribute: attributeId }), callback);
	},

	_updateAttributeSignature : function(keyId, attributeId, signatureId, fields, callback) {
		_updateEntry(this._con, "keys_attributes_signatures", fields, { key: keyId, attribute: attributeId, id: signatureId }, [ "key", "attribute", "id" ], pgp.packetContent.getSignaturePacketInfo, callback);
	},

	_removeAttributeSignature : function(keyId, attributeId, id, callback) {
		_removeEntry(this._con, "keys_attributes_signatures", { key: keyId, attribute: attributeId, id: id }, [ "key", "attribute", "id" ], pgp.packetContent.getSignaturePacketInfo, callback);
	},

	saveChanges : function(callback) {
		_transactionCommand(this._con, "COMMIT", callback);
	},

	revertChanges : function(callback) {
		_transactionCommand(this._con, "ROLLBACK", callback);
	},

	searchIdentities : function(searchString) {
		var query = 'SELECT "keys"."id" AS "keyId", "keys"."expires" AS "keyExpires", "keys"."revoked" AS "keyRevoked", "found"."id" AS "id", "found"."name" AS "name", "found"."email" AS "email", "found"."expires" AS "expires", "found"."revoked" AS "revoked" FROM "keys_identities_selfsigned" AS "found", "keys" WHERE "found"."key" = "keys"."id" AND "found"."id" LIKE \'%\' || $1 || \'%\'';
		return pgp.Fifo.map(db.fifoQuery(this._con, query, [ searchString ]), function(record, callback) {
			callback(null, { id: record.keyId, revoked: record.keyRevoked, expires: record.keyExpires, identity: { id: record.id, name: record.name, email: record.email, expires: record.expires, revoked: record.revoked }});
		});
	},

	searchByShortKeyId : function(keyId) {
		return _filterKeyResults(this, this.getKeys({ id: new pgp.Keyring.Filter.ShortKeyId(keyId) }, [ "id", "expires", "revoked" ]));
	},

	searchByLongKeyId : function(keyId) {
		return _filterKeyResults(this, this.getKeys({ id: keyId.toUpperCase() }, [ "id", "expires", "revoked" ]));
	},

	searchByFingerprint : function(keyId) {
		return _filterKeyResults(this, this.getKeys({ fingerprint: keyId.toUpperCase() }, [ "id", "expires", "revoked" ]));
	}
});

function _splitFilter(filter, tableFields) {
	var ret = {
		db : { },
		js : { }
	};

	if(filter)
	{
		for(var i in filter)
		{
			var f = pgp.Keyring.Filter.get(filter[i]);

			if(tableFields.indexOf(i) == -1 || !f.toPostgresCondition || f.toPostgresCondition(i, [ ]) == null)
				ret.js[i] = f;
			else
				ret.db[i] = f;
		}
	}

	return ret;
}

function _getEntries(con, table, filter, fields, getPacketInfo) {
	var fetchFields = { };
	var shouldGetPacketInfo = false;
	if(fields)
	{
		for(var i=0; i<fields.length; i++)
		{
			if(tableFields[table].indexOf(fields[i]) == -1)
				shouldGetPacketInfo = true;
			else
				fetchFields[fields[i]] = true;
		}
	}
	else
	{
		for(var i=0; i<tableFields[table].length; i++)
			fetchFields[tableFields[table][i]] = true;
		shouldGetPacketInfo = true;
	}

	var filterSplit = _splitFilter(filter, tableFields[table]);
	for(var i in filterSplit.js)
	{
		if(tableFields[table].indexOf(i) == -1)
			shouldGetPacketInfo = true;
		else
			fetchFields[i] = true;
	}

	if(shouldGetPacketInfo)
		fetchFields["binary"] = true;

	// Nasty hack to live without the "binary" column for identities
	if(table == "keys_identities" && fetchFields["binary"])
	{
		fetchFields["id"] = true;
		delete fetchFields["binary"];
	}


	fetchFields = Object.keys(fetchFields);

	var ret = db.getEntries(con, table, fetchFields, filterSplit.db);

	// Nasty hack to live without the "binary" column for identities
	if(table == "keys_identities")
	{
		ret = pgp.Fifo.map(ret, function(identityInfo, cb) {
			if(identityInfo.id != null)
				identityInfo.binary = new Buffer(identityInfo.id, "utf8");
			cb(null, identityInfo);
		});
	}

	if(shouldGetPacketInfo)
	{
		ret = pgp.Fifo.map(ret, function(item, callback) {
			getPacketInfo(item.binary, function(err, packetInfo) {
				if(err)
					return callback(err);
				callback(null, pgp.Keyring._strip(pgp.utils.extend(packetInfo, item), fields));
			});
		});
	}

	ret = pgp.Keyring._filter(ret, filterSplit.js);

	return ret;
}

function _getList(con, table, idField, filter, getPacketInfo) {
	var entries = _getEntries(con, table, filter, [ idField ], getPacketInfo);
	return pgp.Fifo.map(entries, function(item, callback) {
		callback(null, item[idField]);
	});
}

// TODO: Only fetch 1
function _getEntry(con, table, filter, fields, getPacketInfo, callback) {
	var entries = _getEntries(con, table, filter, fields, getPacketInfo);

	entries.next(function(err, entry) {
		if(err === true)
			callback(null, null);
		else
			callback(err, entry);
	});
}

// TODO: Only fetch 1
function _exists(con, table, filter, getPacketInfo, callback) {
	var entries = _getEntries(con, table, filter, [ ], getPacketInfo);

	entries.next(function(err) {
		if(err === true)
			callback(null, false);
		else if(err)
			callback(err);
		else
			callback(null, true);
	});
}

function _getSetFields(table, fields) {
	var ret = { };
	for(var i in fields)
	{
		if(tableFields[table].indexOf(i) != -1)
			ret[i] = fields[i];
	}
	return ret;
}

function _addEntry(con, table, fields, callback) {
	async.series([
		async.apply(_startTransaction, con),
		async.apply(db.insert, con, table, _getSetFields(table, fields))
	], callback);
}

function _updateOrRemoveEntry(con, table, filter, idFields, getPacketInfo, callback, func) {
	async.waterfall([
		async.apply(_startTransaction, con),
		function(callback) {
			var filterSplit = _splitFilter(filter, tableFields[table]);

			if(Object.keys(_splitFilter(filter, tableFields[table]).js).length == 0)
				func(filter, callback);
			else
			{
				_getEntries(con, table, filter, idFields, getPacketInfo).forEachSeries(function(record, next) {
					var thisFilter = { };
					for(var i=0; i<idFields.length; i++)
						thisFilter[idFields[i]] = record[idFields[i]];
					func(thisFilter, next);
				}, callback);
			}
		}
	], callback);
}

function _updateEntry(con, table, fields, filter, idFields, getPacketInfo, callback) {
	var fields = _getSetFields(table, fields);
	if(Object.keys(fields).length == 0)
		return callback(null);

	_updateOrRemoveEntry(con, table, filter, idFields, getPacketInfo, callback, function(filter, callback) {
		db.update(con, table, fields, filter, callback);
	});
}

function _removeEntry(con, table, filter, idFields, getPacketInfo, callback) {
	_updateOrRemoveEntry(con, table, filter, idFields, callback, getPacketInfo, function(filter, callback) {
		db.remove(con, table, filter, callback);
	});
}

function _isSubkey(con, keyId, callback) {
	db.entryExists(this._con, "keys_signatures", { key: keyId, sigtype: SUBKEY_SIGTYPES }, callback);
}

function _isMainKey(con, keyId, exceptSubkeyId, callback) {
	async.waterfall([
		function(next) {
			db.entryExists(con, "keys_signatures", { key: keyId, sigtype: KEY_SIGTYPES }, next);
		},
		function(next) {
			// Check for subkeys except exceptSubkeyId
			if(exists)
				callback(null, true);
			else
				db.entryExists(con, "keys_signatures", { issuer: keyId, sigtype: SUBKEY_SIGTYPES, key: pgp.Keyring.Filter.Not(exceptSubkeyId) }, next);
		},
		function(exists, next) {
			if(exists)
				callback(null, true);
			else
				db.entryExists(con, "keys_identities", { key: keyId }, next);
		},
		function(exists, next) {
			if(exists)
				callback(null, true);
			else
				db.entryExists(con, "keys_attributes", { key: keyId }, next);
		}
	], callback);
}

function _startTransaction(con, callback) {
	_transactionCommand(con, "BEGIN", callback);
}

function _transactionCommand(con, command, callback) {
	if(con._transactionChanging)
		con._transactionChangingCallbacks.push(async.apply(_transactionCommand, con, command, callback));
	else if(con._transactionStarted && command == "BEGIN" || !con._transactionStarted && command != "BEGIN")
		callback(null);
	else
	{
		con._transactionChanging = true;
		con._transactionChangingCallbacks = [ callback ];
		db.query(con, command, [ ], function(err) {
			con._transactionChanging = false;
			con._transactionStarted = (command == "BEGIN");
			for(var i=0; i<con._transactionChangingCallbacks.length; i++)
				con._transactionChangingCallbacks[i].apply(null, arguments);
		});
	}
}

function _filterKeyResults(keyring, result) {
	var ret = new pgp.Fifo();
	result.forEachSeries(function(it, next) {
		async.auto({
			identities: async.apply(_exists, keyring._con, "keys_identities", { key: it.id }, null),
			attributes: async.apply(_exists, keyring._con, "keys_attributes", { key: it.id }, null),
			subkeys: async.apply(_exists, keyring._con, "keys_subkeys", { parentkey: it.id }, null),
			signatures: async.apply(_exists, keyring._con, "keys_signatures", { key: it.id }, null),
			addKey: [ "identities", "attributes", "subkeys", "signatures", function(next, results) {
				if(results.identities || results.attributes || results.subkeys || results.signatures)
					ret._add(it);
				next();
			} ],
			addParentKeys: [ "addKey", function(next, results) {
				_getEntries(keyring._con, "keys_subkeys", { id: it.id }, [ "parentkey", "expires", "revoked" ], null).forEachSeries(function(it2, next) {
					keyring.getKey(it2.parentkey, function(err, key) {
						if(err)
							return next(err);
						key.subkey = pgp.utils.extend({ }, it, { expires: it2.expires, revoked: it2.revoked });
						ret._add(key);
						next();
					}, [ "id", "expires", "revoked" ]);
				}, next);
			} ]
		}, next);
	}, pgp.utils.proxy(ret, ret._end));

	return ret;
}

exports.getKeyring = getKeyring;
exports.initialiseDatabase = initialiseDatabase;
exports._KeyringPostgres = _KeyringPostgres;