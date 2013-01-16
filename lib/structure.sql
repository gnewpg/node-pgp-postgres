CREATE TABLE "keys" (
	"id" CHAR(16) PRIMARY KEY, -- Long ID of the key
	"fingerprint" VARCHAR(40) NOT NULL UNIQUE, -- Fingerprint of the key, 32 chars for v2/v3 keys, 40 chars for v4 keys
	"binary" bytea NOT NULL,
	"date" TIMESTAMP WITH TIME ZONE NOT NULL,
	"expires" TIMESTAMP WITH TIME ZONE DEFAULT NULL,
	"revoked" CHAR(27) DEFAULT NULL, -- This can reference all three signature tables
	"security" SMALLINT NOT NULL
	-- "primary_identity" TEXT DEFAULT NULL -- Added later, table "identities" is not defined yet here
);

CREATE INDEX "keys_shortid_idx" ON "keys" (SUBSTRING("id" FROM 8 FOR 8));

CREATE TABLE "keys_signatures" (
	"id" CHAR(27) NOT NULL,
	"key" CHAR(16) NOT NULL REFERENCES "keys"("id"),
	"issuer" CHAR(16) NOT NULL, -- Long ID of the key that made the signature. Not a foreign key as the key might be a subkey or unknown
	"date" TIMESTAMP WITH TIME ZONE NOT NULL,
	"binary" bytea NOT NULL,
	"verified" BOOLEAN NOT NULL DEFAULT false,
	"sigtype" SMALLINT NOT NULL CHECK ("sigtype" IN (25, 31, 32, 24, 40, 48)), -- 0x19, 0x1F, 0x20, 0x18, 0x28, 0x30
	"expires" TIMESTAMP WITH TIME ZONE,
	"revoked" CHAR(27) DEFAULT NULL,
	"security" SMALLINT NOT NULL,

	UNIQUE("id", "key")
);

CREATE INDEX "keys_signatures_key_idx" ON "keys_signatures" ("key");
CREATE INDEX "keys_signatures_issuer_idx" ON "keys_signatures" ("issuer");

CREATE VIEW "keys_subkeys" AS SELECT DISTINCT ON ( "id", "parentkey" )
	"keys"."id" AS "id",
	"keys"."fingerprint" AS "fingerprint",
	"keys"."binary" AS "binary",
	"keys"."date" AS "date",
	"keys_signatures"."issuer" AS "parentkey",
	"keys"."security" AS "security"
	FROM "keys", "keys_signatures" WHERE "keys_signatures"."key" = "keys"."id" AND "keys_signatures"."sigtype" IN ( 24, 40 ) -- 24 == 0x18, 40 == 0x28
;

CREATE VIEW "keys_subkeys_selfsigned" AS SELECT DISTINCT ON ( "id", "parentkey" )
	"keys"."id" AS "id",
	"keys"."fingerprint" AS "fingerprint",
	"keys"."binary" AS "binary",
	"keys"."date" AS "date",
	"keys_signatures"."issuer" AS "parentkey",
	"keys_signatures"."expires" AS "expires",
	"keys_signatures"."revoked" AS "revoked",
	LEAST("keys_signatures"."security", "keys"."security") AS "security"
	FROM "keys", "keys_signatures" WHERE "keys_signatures"."key" = "keys"."id" AND "keys_signatures"."verified" = true AND "keys_signatures"."sigtype" = 24 AND "keys_signatures"."security" >= 1 -- 24 == 0x18
;

-----------------------------------------------------

CREATE TABLE "keys_identities" (
	"id" TEXT NOT NULL, -- The ID is simply the text of the identity, thus only unique per key
	"key" CHAR(16) NOT NULL REFERENCES "keys"("id"),
	"name" TEXT NOT NULL,
	"email" TEXT,

	PRIMARY KEY("id", "key")
);

CREATE INDEX "keys_identities_key_idx" ON "keys_identities"("key");

CREATE TABLE "keys_identities_signatures" (
	"id" CHAR(27) NOT NULL,
	"identity" TEXT NOT NULL,
	"key" CHAR(16) NOT NULL,
	"issuer" CHAR(16) NOT NULL, -- Long ID of the key that made the signature. Not a foreign key as the key might be unknown
	"date" TIMESTAMP WITH TIME ZONE NOT NULL,
	"binary" bytea NOT NULL,
	"verified" BOOLEAN NOT NULL DEFAULT false,
	"sigtype" SMALLINT NOT NULL CHECK ("sigtype" IN (16, 17, 18, 19, 48)), --0x10, 0x11, 0x12, 0x13, 0x30
	"expires" TIMESTAMP WITH TIME ZONE,
	"revoked" CHAR(27) DEFAULT NULL,
	"security" SMALLINT NOT NULL,

	UNIQUE ("id", "identity", "key"),
	FOREIGN KEY ("identity", "key") REFERENCES "keys_identities" ( "id", "key" )
);

CREATE INDEX "keys_identities_signatures_key_idx" ON "keys_identities_signatures" ("key", "identity");
CREATE INDEX "keys_identities_signatures_issuer_idx" ON "keys_identities_signatures" ("issuer");

CREATE VIEW "keys_identities_selfsigned" AS
	SELECT DISTINCT ON ( "id", "key" )
		"keys_identities".*, "keys_identities_signatures"."expires", "keys_identities_signatures"."revoked",
		"keys_identities_signatures"."security"
		FROM "keys_identities", "keys_identities_signatures"
		WHERE "keys_identities"."key" = "keys_identities_signatures"."key" AND "keys_identities"."id" = "keys_identities_signatures"."identity"
			AND "keys_identities"."key" = "keys_identities_signatures"."issuer" AND "keys_identities_signatures"."verified" = true
			AND "keys_identities_signatures"."sigtype" IN (16, 17, 18, 19)
			AND "keys_identities_signatures"."security" > 0
		ORDER BY "keys_identities"."id" ASC, "keys_identities"."key" ASC, "keys_identities_signatures"."date" DESC
;

ALTER TABLE "keys"
	ADD COLUMN "primary_identity" TEXT DEFAULT NULL,
	ADD FOREIGN KEY ("primary_identity", "id") REFERENCES "keys_identities" ("id", "key");

-----------------------------------------------------

CREATE TABLE "keys_attributes" (
	"id" CHAR(27) NOT NULL, -- The ID is the sha1sum of the content, thus only unique per key
	"key" CHAR(16) NOT NULL REFERENCES "keys"("id"),
	"binary" BYTEA NOT NULL,

	PRIMARY KEY("id", "key")
);

CREATE TABLE "keys_attributes_signatures" (
	"id" CHAR(27) NOT NULL,
	"attribute" CHAR(27) NOT NULL,
	"key" CHAR(16) NOT NULL,
	"issuer" CHAR(16) NOT NULL, -- Long ID of the key that made the signature. Not a foreign key as the key might be unknown
	"date" TIMESTAMP WITH TIME ZONE NOT NULL,
	"binary" bytea NOT NULL,
	"verified" BOOLEAN NOT NULL DEFAULT false,
	"sigtype" SMALLINT NOT NULL CHECK ("sigtype" IN (16, 17, 18, 19, 48)), --0x10, 0x11, 0x12, 0x13, 0x30
	"expires" TIMESTAMP WITH TIME ZONE,
	"revoked" CHAR(27) DEFAULT NULL,
	"security" SMALLINT NOT NULL,

	UNIQUE ( "id", "attribute", "key" ),
	FOREIGN KEY ("attribute", "key") REFERENCES "keys_attributes"("id", "key")
);

CREATE INDEX "keys_attributes_signatures_key_idx" ON "keys_attributes_signatures" ("key", "attribute");
CREATE INDEX "keys_attributes_signatures_issuer_idx" ON "keys_attributes_signatures" ("issuer");

CREATE VIEW "keys_attributes_selfsigned" AS
	SELECT DISTINCT ON ( "id", "key" )
		"keys_attributes".*, "keys_attributes_signatures"."expires", "keys_attributes_signatures"."revoked",
		"keys_attributes_signatures"."security"
		FROM "keys_attributes", "keys_attributes_signatures"
		WHERE "keys_attributes"."key" = "keys_attributes_signatures"."key" AND "keys_attributes"."id" = "keys_attributes_signatures"."attribute"
			AND "keys_attributes"."key" = "keys_attributes_signatures"."issuer" AND "keys_attributes_signatures"."verified" = true
			AND "keys_attributes_signatures"."sigtype" IN (16, 17, 18, 19)
			AND "keys_attributes_signatures"."security" > 0
		ORDER BY "keys_attributes"."id" ASC, "keys_attributes"."key" ASC, "keys_attributes_signatures"."date" DESC
;

-----------------------------------------------------

CREATE VIEW "keys_signatures_all" AS
	      SELECT "id", "key", "issuer", "date", "binary", "verified", "sigtype", "expires", "revoked", NULL AS "objectId", 'key' AS "type" FROM "keys_signatures"
	UNION SELECT "id", "key", "issuer", "date", "binary", "verified", "sigtype", "expires", "revoked", "identity" AS "objectId", 'identity' AS "type" FROM "keys_identities_signatures"
	UNION SELECT "id", "key", "issuer", "date", "binary", "verified", "sigtype", "expires", "revoked", "attribute" AS "objectId", 'attribute' AS "type" FROM "keys_attributes_signatures"
;