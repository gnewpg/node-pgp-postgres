node-pgp-postgres is a PostgreSQL backend for [node-pgp](https://github.com/cdauth/node-pgp).
It provides an implementation of the Keyring class that stores keys in database tables.

Use the following code to create an instance of the Keyring class:

```javascript
var pgpPg = require("node-pgp-postgres");
pgpPg.getKeyring("postgres://postgres@localhost/database", function(err, keyring) {
	if(err)
		; // An error occurred

	// Now we do some stuff with the keyring

	// Once we are finished, we release the database connection:
	keyring.done();
}, true); // If the last parameter is set to true, the database layout will be initialised automatically
```

The connection string uses the [format of node-postgres](https://github.com/brianc/node-postgres#examples).
It may also be specified as an object of the following format:
```javascript
{
	user: "postgres",
	password: "password",
	host: "localhost",
	port: 1234,
	database: "database",
	schema: "public"
}
```