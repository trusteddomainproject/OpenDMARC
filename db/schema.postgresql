-- =============================================================
-- Project:   OpenDMARC database schema for PostgreSQL
-- Filename:  db/schema.postgresql
-- Author:    Randolf Richardson <randolf@inter-corporate.com>
--
-- Copyright (c) 2024, The Trusted Domain Project.
--    All rights reserved.
--
-- This schema is the first step in adding PostgreSQL support to
-- OpenDMARC.  Many people have been asking how to configure
-- PostgreSQL database support, so I proceeded to write this
-- schema to serve as the foundation for this.
--
-- My style of writing SQL code includes detailed comments both
-- in the SQL script itself and on the tables and columns (use
-- the "\d+ table-name" command in psql to see these commnets),
-- which I believe simplifies software maintenance for everyone,
-- and which I hope will encourage more people to write more
-- documentation in the future.  The trade-off of time to write
-- more detailed documentation (at least 5 hours in this case)
-- is, in my experience, always advantagious in the long-run.
--
-- Tested with the following versions of PostgreSQL:
--    PostgreSQL v14 (Debian Linux)
--
-- Referential integrity is implemented in this database schema,
-- some constraint checks have been added to enforce ranges, and
-- testing will be needed as Perl DBI code is added to support
-- PostgreSQL.  At least some of the indexes added may not be
-- needed, and should be removed as reviewing queries clarifies
-- this.
--
-- =============================================================
-- Create new database, configure error handing, and switch to
-- the new database.  If the database already exists, that error
-- can be ignored, but if the rest of the schema encounters any
-- errors, then the entire operation will be rolled back.  We
-- use a PostgreSQL transaction to ensure that only a complete
-- schema is created (incomplete schemas can lead to subtle and
-- unexpected problems that can be difficult to troubleshoot).
--
CREATE DATABASE opendmarc;
\set ON_ERROR_STOP on
\c opendmarc

-- =============================================================
-- Beginning of SQL commands.  If anything fails, the entire set
-- of commands will be rolled back, which prevents a partial
-- implementation from being installed.
--
BEGIN;

-- =============================================================
-- Table "domains" maps domain names to unique IDs,
-- automatically tracks a "first seen" timestamp, and includes a
-- column to record when the last report was sent.
--
CREATE TABLE domains (

	-- -------------------------------------------------------------
	-- Unique ID number.
	--
	id		BIGSERIAL	not null primary key,

	-- -------------------------------------------------------------
	-- Domain name.  The maximum length is 255 octets according to
	-- RFC 1035 (see the entry for "names" in section 2.3.4).
	--
	name		VARCHAR(255)	not null unique,

	-- -------------------------------------------------------------
	-- Date and time this row was created.
	--
	firstseen	TIMESTAMPTZ	not null default CURRENT_TIMESTAMP

); -- TABLE domains
COMMENT ON TABLE	domains				IS 'Map domain names and DMARC policies to IDs';
COMMENT ON COLUMN	domains.id			IS 'Unique ID number';
COMMENT ON COLUMN	domains.name			IS 'Domain name';
COMMENT ON COLUMN	domains.firstseen		IS 'When this row was created';
CREATE INDEX ON		domains(id);
CREATE INDEX ON		domains(name);
CREATE INDEX ON		domains(firstseen);

-- =============================================================
-- Table "selectors" maps selector names to unique IDs,
-- automatically tracks a "first seen" timestamp, and references
-- the domain that owns the selector.
--
CREATE TABLE selectors (

	-- -------------------------------------------------------------
	-- Unique ID number.
	--
	id		BIGSERIAL	not null primary key,

	-- -------------------------------------------------------------
	-- Domain name ID.
	--
	domain		BIGINT		not null references domains(id),

	-- -------------------------------------------------------------
	-- Selector name.
	--
	name		VARCHAR(255)	not null unique,

	-- -------------------------------------------------------------
	-- Date and time this row was created.
	--
	firstseen	TIMESTAMPTZ	not null default CURRENT_TIMESTAMP,

	-- -------------------------------------------------------------
	-- Set up unique combination pair.
	--
	UNIQUE (name, domain)

); -- TABLE selectors
COMMENT ON TABLE	selectors			IS 'Log encountered ARC selectors';
COMMENT ON COLUMN	selectors.id			IS 'Unique ID number';
COMMENT ON COLUMN	selectors.domain		IS 'Domain name ID foreign-key';
COMMENT ON COLUMN	selectors.name			IS 'Selector name';
COMMENT ON COLUMN	selectors.firstseen		IS 'When this row was created';
CREATE INDEX ON		selectors(id);
CREATE INDEX ON		selectors(domain);
CREATE INDEX ON		selectors(name);
CREATE INDEX ON		selectors(firstseen);

-- =============================================================
-- Table "requests" is caches DMARC reporting requests.  For
-- each domain, the destination reporting URI for aggregate
-- reports is recorded along with a last-report-sent timestamp.
--
CREATE TABLE requests (

	-- -------------------------------------------------------------
	-- Unique ID number.
	--
	id		BIGSERIAL	not null primary key,

	-- -------------------------------------------------------------
	-- Domain name ID.
	--
	domain		BIGINT		not null references domains(id),

	-- -------------------------------------------------------------
	-- Reporting URI.
	--
	-- 8,000 octets is the "recommended" maxumum length of a URI
	-- according to RFC 7230 (see last paragraph of section 3.1.1)
	-- and RFC 9110 (see last paragraph of section 4.1).
	--
	repuri		VARCHAR(8000)	not null default '',

	-- -------------------------------------------------------------
	-- DMARC alignment rules for DKIM (adkim) and SPF (aspf).
	--
	--    114 = relaxed (e.g., "adkim=r" or "aspf=s" in DNS record)
	--    115 = strict  (e.g., "adkim=s" or "aspf=s" in DNS record)
	--
	-- Normally I would limit the values on these two columns, but I
	-- don't know if there will be other options added in future
	-- specfiications, and my personal preference would be to use
	-- the "r" and "s" characters and limit to these.  But alas, for
	-- now I think it's best to just leave things as they are in the
	-- interests of better reliability and development expectations
	-- since it's unclear why 0 is the default (I assume that 0
	-- indicates the absence of an alignment rule, but this needs to
	-- be verified).
	--
	adkim		SMALLINT	not null default 0,
	aspf		SMALLINT	not null default 0,

	-- -------------------------------------------------------------
	-- DMARC policy.  This is the "p=" parameter in the DNS record,
	-- which, according to RFC 7489 (see last half of the second
	-- page in section 6.3) can be set to a "none," "quarantine," or
	-- "reject" policy value.
	--
	--   14 = unknown (no record found)
	--   15 = pass
	--   16 = reject
	--   17 = quarantine
	--   18 = none
	--
	-- The "sp=" parameter is the sub-domain policy, recorded in the
	-- "spolicy" column (see the entry for "sp" on the fourth page
	-- in section 6.3 in RFC 7489).  Byy default, "sp=" falls back
	-- to the "p=" parameter when not specified in the DNS record.
	--
	policy		SMALLINT	not null,
	spolicy		SMALLINT	not null,

	-- -------------------------------------------------------------
	-- Percentage of messages that DMARC policy should apply to; 100
	-- is the default according to RFC 7489 (see the last paragraph
	-- on the second page in section 6.3).
	--
	pct		SMALLINT	not null default 100 CHECK(pct BETWEEN 0 AND 100),

	-- -------------------------------------------------------------
	-- This is used during report generation.
	--
	-- The problem that this attempts to solve should be resolved by
	-- using a transaction to isolate the queries in a robust way.
	--
	locked		BOOL		not null default FALSE,

	-- -------------------------------------------------------------
	-- Date and time this row was created, and when the request was
        -- most recently sent.
	--
	firstseen	TIMESTAMPTZ	not null default CURRENT_TIMESTAMP,
	lastsent	TIMESTAMPTZ	not null default CURRENT_TIMESTAMP

); -- TABLE requests
COMMENT ON TABLE	requests			IS 'Log reporting requests';
COMMENT ON COLUMN	requests.id			IS 'Unique ID number';
COMMENT ON COLUMN	requests.domain			IS 'Domain name ID foreign-key';
COMMENT ON COLUMN	requests.repuri			IS 'Reporting URI';
COMMENT ON COLUMN	requests.adkim			IS 'DKIM alignment rule';
COMMENT ON COLUMN	requests.aspf			IS 'SPF alignment rule';
COMMENT ON COLUMN	requests.policy			IS 'Domain policy';
COMMENT ON COLUMN	requests.spolicy		IS 'Sub-domain policy';
COMMENT ON COLUMN	requests.pct			IS 'Effectiveness percentage';
COMMENT ON COLUMN	requests.locked			IS 'Flag:  Used for report generation';
COMMENT ON COLUMN	requests.firstseen		IS 'When this row was created';
COMMENT ON COLUMN	requests.lastsent		IS 'When this request was sent';
CREATE INDEX ON		requests(id);
CREATE INDEX ON		requests(domain);
CREATE INDEX ON		requests(repuri);
CREATE INDEX ON		requests(adkim);
CREATE INDEX ON		requests(aspf);
CREATE INDEX ON		requests(policy);
CREATE INDEX ON		requests(spolicy);
CREATE INDEX ON		requests(pct);
CREATE INDEX ON		requests(locked);
CREATE INDEX ON		requests(firstseen);
CREATE INDEX ON		requests(lastsent);

-- =============================================================
-- Table "reporters" is used for reporting hosts.
--
CREATE TABLE reporters (

	-- -------------------------------------------------------------
	-- Unique ID number.
	--
	id		BIGSERIAL	not null primary key,

	-- -------------------------------------------------------------
	-- Selector name.
	--
	name		VARCHAR(255)	not null unique,

	-- -------------------------------------------------------------
	-- Date and time this row was created.
	--
	firstseen	TIMESTAMPTZ	not null default CURRENT_TIMESTAMP

); -- TABLE reporters
COMMENT ON TABLE	reporters			IS 'Table for reporting hosts';
COMMENT ON COLUMN	reporters.id			IS 'Unique ID number';
COMMENT ON COLUMN	reporters.name			IS 'Selector name';
COMMENT ON COLUMN	reporters.firstseen		IS 'When this row was created';
CREATE INDEX ON		reporters(id);
CREATE INDEX ON		reporters(name);
CREATE INDEX ON		reporters(firstseen);

-- =============================================================
-- Table "ipaddr" maps IP addresses to unique IDs, along with a
-- "first seen" timestamp.
--
CREATE TABLE ipaddr (

	-- -------------------------------------------------------------
	-- Unique ID number.
	--
	id		BIGSERIAL	not null primary key,

	-- -------------------------------------------------------------
	-- Client's IP address.
	--
	addr		CIDR		not null unique,

	-- -------------------------------------------------------------
	-- Date and time this row was created.
	--
	firstseen	TIMESTAMPTZ	not null default CURRENT_TIMESTAMP

); -- TABLE ipaddr
COMMENT ON TABLE	ipaddr				IS 'Table for connecting client IP addresses';
COMMENT ON COLUMN	ipaddr.id			IS 'Unique ID number';
COMMENT ON COLUMN	ipaddr.addr			IS 'Client''s IP address';
COMMENT ON COLUMN	ipaddr.firstseen		IS 'When this row was created';
CREATE INDEX ON		ipaddr(id);
CREATE INDEX ON		ipaddr(addr);
CREATE INDEX ON		ipaddr(firstseen);

-- =============================================================
-- Table "messages" tracks salient properties of all messages
-- received.  Each message is uniquely identified by a
-- date-jobid-reporter tuple.
--
-- References to the "domains" table track the RFC5321.MailFrom
-- and RFC5322.From domains.
--
-- The count of DKIM signatures, the SPF result, and whether or
-- not the SPF result was aligned with the RFC5322.From domain
-- is also tracked.
--
CREATE TABLE messages (

	-- -------------------------------------------------------------
	-- Unique ID number.
	--
	id		BIGSERIAL	not null primary key,

	-- -------------------------------------------------------------
	-- Date and time of this message.
	--
	date		TIMESTAMPTZ	not null default CURRENT_TIMESTAMP,

	-- -------------------------------------------------------------
	-- Job ID.
	--
	jobid		VARCHAR(128)	not null,

	-- -------------------------------------------------------------
	-- Reporter ID.
	--
	reporter	BIGINT		not null references reporters(id),

	-- -------------------------------------------------------------
	-- DMARC policy.  This is the "p=" parameter in the DNS record,
	-- which, according to RFC 7489 (see last half of the second
	-- page in section 6.3) can be set to a "none," "quarantine," or
	-- "reject" policy value.
	--
	--   14 = unknown (no record found)
	--   15 = pass
	--   16 = reject
	--   17 = quarantine
	--   18 = none
	--
	policy		SMALLINT	not null,

	-- -------------------------------------------------------------
	-- Action:
	--
	--    0 = reject
	--    1 = reject
	--    2 = none
	--    4 = quarantine
	--    ? = unknown (all other values)
	--
	disp		BIGINT		not null references reporters(id),

	-- -------------------------------------------------------------
	-- IP address ID.
	--
	ip		BIGINT		not null references ipaddr(id),

	-- -------------------------------------------------------------
	-- Envelope, From, and Policy domains ID.
	--
	env_domain	BIGINT		not null references domains(id),
	from_domain	BIGINT		not null references domains(id),
	policy_domain	BIGINT		not null references domains(id),

	-- -------------------------------------------------------------
	-- SPF result?  (This column needs to be documented.)
	--
	spf		INT		not null,

	-- -------------------------------------------------------------
	-- DMARC alignment rules for DKIM (adkim) and SPF (aspf).
	--
	--    114 = relaxed (e.g., "adkim=r" or "aspf=s" in DNS record)
	--    115 = strict  (e.g., "adkim=s" or "aspf=s" in DNS record)
	--
	-- Normally I would limit the values on these two columns, but I
	-- don't know if there will be other options added in future
	-- specfiications, and my personal preference would be to use
	-- the "r" and "s" characters and limit to these.  But alas, for
	-- now I think it's best to just leave things as they are in the
	-- interests of better reliability and development expectations
	-- since it's unclear why 0 is the default in the "requests"
	-- table (I assume that 0 indicates the absence of an alignment
	-- rule, but this needs to be verified).
	--
	align_dkim	SMALLINT	not null,
	align_spf	SMALLINT	not null,

	-- -------------------------------------------------------------
	-- Signature count.  (This column needs to be documented.)
	--
	sigcount	INT		not null,

	-- -------------------------------------------------------------
	-- ARC and ARC policy.  (These columns need to be documented.)
	--
	arc		INT		not null,
	arc_policy	INT		not null,

	-- -------------------------------------------------------------
	-- Set up unique combination set.
	--
	UNIQUE (reporter, date, jobid)

); -- TABLE messages
COMMENT ON TABLE	messages			IS 'Messages';
COMMENT ON COLUMN	messages.id			IS 'Unique ID number';
COMMENT ON COLUMN	messages.jobid			IS 'Job ID';
COMMENT ON COLUMN	messages.reporter		IS 'Reporter ID foreign-key';
COMMENT ON COLUMN	messages.policy			IS 'Domain policy';
COMMENT ON COLUMN	messages.disp			IS 'Action';
COMMENT ON COLUMN	messages.ip			IS 'IP address foreign-key';
COMMENT ON COLUMN	messages.env_domain		IS 'Envelope domain ID foreign-key';
COMMENT ON COLUMN	messages.from_domain		IS 'From domain ID foreign-key';
COMMENT ON COLUMN	messages.policy_domain		IS 'Policy domain ID foreign-key';
COMMENT ON COLUMN	messages.spf			IS 'SPF result? (needs to be documented)';
COMMENT ON COLUMN	messages.align_dkim		IS 'DKIM alignment';
COMMENT ON COLUMN	messages.align_spf		IS 'SPF alignment';
COMMENT ON COLUMN	messages.sigcount		IS 'Signature count (needs to be documented)';
COMMENT ON COLUMN	messages.arc			IS 'ARC (needs to be documented)';
COMMENT ON COLUMN	messages.arc_policy		IS 'ARC policy (needs to be documented)';
CREATE INDEX ON		messages(id);
CREATE INDEX ON		messages(jobid);
CREATE INDEX ON		messages(reporter);
CREATE INDEX ON		messages(policy);
CREATE INDEX ON		messages(disp);
CREATE INDEX ON		messages(ip);
CREATE INDEX ON		messages(env_domain);
CREATE INDEX ON		messages(from_domain);
CREATE INDEX ON		messages(policy_domain);
CREATE INDEX ON		messages(spf);
CREATE INDEX ON		messages(align_dkim);
CREATE INDEX ON		messages(align_spf);
CREATE INDEX ON		messages(sigcount);
CREATE INDEX ON		messages(arc);
CREATE INDEX ON		messages(arc_policy);

-- =============================================================
-- Table "signatures" tracks DKIM signatures, each of which
-- refers to a row in the "messages" table.
--
-- Also tracked is the signing domain, whether the signature
-- passed, whether there was a verification error other than a
-- broken signature, and whether or not the signing domain
-- aligned with the RFC5322.From domain.
--
CREATE TABLE signatures (

	-- -------------------------------------------------------------
	-- Unique ID number.
	--
	id		BIGSERIAL	not null primary key,

	-- -------------------------------------------------------------
	-- Reference to ID number in "messages" table.
	--
	message		BIGINT		not null references messages(id),

	-- -------------------------------------------------------------
	-- Domain ID.
	--
	domain		BIGINT		not null references domains(id),

	-- -------------------------------------------------------------
	-- Selector ID.
	--
	selector	BIGINT		not null references selectors(id),

	-- -------------------------------------------------------------
	-- Pass status and error status of DKIM signature.
	--
	-- Can the "error" column type be BOOL?  If so, we should change
	-- this column's type accordingly.
	--
	pass		BOOL		not null,
	error		SMALLINT	not null

); -- TABLE signatures
COMMENT ON TABLE	signatures			IS 'DKIM signature tracking';
COMMENT ON COLUMN	signatures.id			IS 'Unique ID number';
COMMENT ON COLUMN	signatures.message		IS 'Message ID foreign-key';
COMMENT ON COLUMN	signatures.domain		IS 'Domain ID foreign-key';
COMMENT ON COLUMN	signatures.selector		IS 'Selector ID foreign-key';
COMMENT ON COLUMN	signatures.pass			IS 'Flag:  Whether the signature passed';
COMMENT ON COLUMN	signatures.error		IS 'Error, other than broken signature';
CREATE INDEX ON		signatures(id);
CREATE INDEX ON		signatures(message);
CREATE INDEX ON		signatures(domain);
CREATE INDEX ON		signatures(selector);

-- =============================================================
-- Table "arcauthresults" logs ARC-Authentication-Results
-- information.
--
CREATE TABLE arcauthresults (

	-- -------------------------------------------------------------
	-- Unique ID number.
	--
	id		BIGSERIAL	not null primary key,

	-- -------------------------------------------------------------
	-- Message ID.
	--
	message		BIGINT		not null references messages(id),

	-- -------------------------------------------------------------
	-- Instance number, which is in the range of 1 through 50 as per
	-- section 4.2.1 of RFC 8617.
	--
	instance	SMALLINT	not null check(instance BETWEEN 1 AND 50),

	-- -------------------------------------------------------------
	-- Client's IP address.
	--
	-- Since '' is not permitted, NULL will be used (the MySQL code
	-- is set to "NOT NULL DEFAULT ''" and doesn't prevent invalid
	-- data such as malformed IP addresses from being inserted).
	--
	arc_client_addr	CIDR,

	-- -------------------------------------------------------------
	-- Set up unique combination pair.
	--
	UNIQUE (message, instance)

); -- TABLE arcauthresults
COMMENT ON TABLE	arcauthresults			IS 'Log ARC-Authentication-Results information';
COMMENT ON COLUMN	arcauthresults.id		IS 'Unique ID number';
COMMENT ON COLUMN	arcauthresults.message		IS 'Messages ID foreign-key';
COMMENT ON COLUMN	arcauthresults.instance		IS 'Instance number (1..50)';
COMMENT ON COLUMN	arcauthresults.arc_client_addr	IS 'Client''s IP address';
CREATE INDEX ON		arcauthresults(id);
CREATE INDEX ON		arcauthresults(message);
CREATE INDEX ON		arcauthresults(instance);
CREATE INDEX ON		arcauthresults(arc_client_addr);

-- =============================================================
-- Table "arcseals" logs ARC-Seal information.
--
CREATE TABLE arcseals (

	-- -------------------------------------------------------------
	-- Unique ID number.
	--
	id		BIGSERIAL	not null primary key,

	-- -------------------------------------------------------------
	-- Message ID.
	--
	message		BIGINT		not null references messages(id),

	-- -------------------------------------------------------------
	-- Domain name ID.
	--
	domain		BIGINT		not null references domains(id),

	-- -------------------------------------------------------------
	-- Selector ID.
	--
	selector	BIGINT		not null references selectors(id),

	-- -------------------------------------------------------------
	-- Instance number, which is in the range of 1 through 50,
	-- according to RFC 8617 (see section 4.2.1).
	--
	instance	SMALLINT	not null check(instance BETWEEN 1 AND 50),

	-- -------------------------------------------------------------
	-- Date and time this row was created.
	--
	firstseen	TIMESTAMPTZ	not null default CURRENT_TIMESTAMP,

	-- -------------------------------------------------------------
	-- Set up unique combination set.
	--
	UNIQUE (message, domain, selector, instance)

); -- TABLE arcseals
COMMENT ON TABLE	arcseals			IS 'Log ARC-Seal information';
COMMENT ON COLUMN	arcseals.id			IS 'Unique ID number';
COMMENT ON COLUMN	arcseals.message		IS 'Messages ID foreign-key';
COMMENT ON COLUMN	arcseals.domain			IS 'Domain name ID foreign-key';
COMMENT ON COLUMN	arcseals.selector		IS 'Selector ID foreign-key';
COMMENT ON COLUMN	arcseals.instance		IS 'Instance number (1..50)';
COMMENT ON COLUMN	arcseals.firstseen		IS 'When this row was created';
CREATE INDEX ON		arcseals(id);
CREATE INDEX ON		arcseals(message);
CREATE INDEX ON		arcseals(domain);
CREATE INDEX ON		arcseals(selector);
CREATE INDEX ON		arcseals(instance);
CREATE INDEX ON		arcseals(firstseen);

-- =============================================================
-- End of SQL commands.
--
COMMIT;
