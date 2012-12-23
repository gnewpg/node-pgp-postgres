var keyring = require("./lib/keyring");

module.exports = {
	getKeyring : keyring.getKeyring,
	initialiseDatabase : keyring.initialiseDatabase,
	_KeyringPostgres : keyring._KeyringPostgres
};