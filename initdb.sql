    -- 1. SAFELY CREATE USER 'pdns' WITH PASSWORD 'pdnspass'
    -- This block checks if the user exists. If not, it creates it.
    -- If it does exist, it ensures the password is correct.
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'pdns') THEN
        CREATE ROLE pdns LOGIN PASSWORD 'pdnspass';
      ELSE
        ALTER ROLE pdns WITH PASSWORD 'pdnspass';
      END IF;
    END
    $$;

    -- 2. SAFELY CREATE DATABASE 'pdns'
    -- We use a psql trick (\gexec) to conditionally run the CREATE DATABASE command
    -- because CREATE DATABASE cannot run inside a DO block.
    SELECT 'CREATE DATABASE pdns OWNER pdns'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'pdns')\gexec

    -- 3. CONNECT TO THE NEW DATABASE
    -- Crucial: We switch context so the tables below are created inside 'pdns', not 'postgres'
    \c pdns

    -- 4. CREATE THE SCHEMA (Tables)
    CREATE TABLE IF NOT EXISTS domains (
      id                    SERIAL PRIMARY KEY,
      name                  VARCHAR(255) NOT NULL,
      master                VARCHAR(128) DEFAULT NULL,
      last_check            INTEGER DEFAULT NULL,
      type                  VARCHAR(6) NOT NULL,
      notified_serial       INTEGER DEFAULT NULL,
      account               VARCHAR(40) DEFAULT NULL,
      CONSTRAINT c_lowercase_name CHECK (((name)::text = lower((name)::text)))
    );
    CREATE UNIQUE INDEX IF NOT EXISTS name_index ON domains(name);

    CREATE TABLE IF NOT EXISTS records (
      id                    BIGSERIAL PRIMARY KEY,
      domain_id             INTEGER DEFAULT NULL,
      name                  VARCHAR(255) DEFAULT NULL,
      type                  VARCHAR(10) DEFAULT NULL,
      content               VARCHAR(65535) DEFAULT NULL,
      ttl                   INTEGER DEFAULT NULL,
      prio                  INTEGER DEFAULT NULL,
      disabled              BOOL DEFAULT 'f',
      ordername             VARCHAR(255),
      auth                  BOOL DEFAULT 't',
      CONSTRAINT domain_exists FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE,
      CONSTRAINT c_lowercase_name CHECK (((name)::text = lower((name)::text)))
    );
    CREATE INDEX IF NOT EXISTS rec_name_index ON records(name);
    CREATE INDEX IF NOT EXISTS nametype_index ON records(name,type);
    CREATE INDEX IF NOT EXISTS domain_id ON records(domain_id);
    CREATE INDEX IF NOT EXISTS recordorder ON records (domain_id, ordername text_pattern_ops);

    CREATE TABLE IF NOT EXISTS supermasters (
      ip                    INET NOT NULL,
      nameserver            VARCHAR(255) NOT NULL,
      account               VARCHAR(40) NOT NULL,
      PRIMARY KEY (ip, nameserver)
    );

    CREATE TABLE IF NOT EXISTS comments (
      id                    SERIAL PRIMARY KEY,
      domain_id             INTEGER NOT NULL,
      name                  VARCHAR(255) NOT NULL,
      type                  VARCHAR(10) NOT NULL,
      modified_at           INTEGER NOT NULL,
      account               VARCHAR(40) DEFAULT NULL,
      comment               VARCHAR(65535) NOT NULL,
      CONSTRAINT domain_exists FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE,
      CONSTRAINT c_lowercase_name CHECK (((name)::text = lower((name)::text)))
    );
    CREATE INDEX IF NOT EXISTS comments_name_type_idx ON comments (name, type);
    CREATE INDEX IF NOT EXISTS comments_order_idx ON comments (domain_id, modified_at);

    CREATE TABLE IF NOT EXISTS domainmetadata (
      id                    SERIAL PRIMARY KEY,
      domain_id             INTEGER REFERENCES domains(id) ON DELETE CASCADE,
      kind                  VARCHAR(32),
      content               TEXT
    );
    CREATE INDEX IF NOT EXISTS domainmetadata_idx ON domainmetadata (domain_id, kind);

    CREATE TABLE IF NOT EXISTS cryptokeys (
      id                    SERIAL PRIMARY KEY,
      domain_id             INTEGER REFERENCES domains(id) ON DELETE CASCADE,
      flags                 INT NOT NULL,
      active                BOOL,
      content               TEXT
    );
    CREATE INDEX IF NOT EXISTS domainidindex ON cryptokeys(domain_id);

    CREATE TABLE IF NOT EXISTS tsigkeys (
      id                    SERIAL PRIMARY KEY,
      name                  VARCHAR(255),
      algorithm             VARCHAR(50),
      secret                VARCHAR(255),
      CONSTRAINT c_lowercase_name CHECK (((name)::text = lower((name)::text)))
    );
    CREATE UNIQUE INDEX IF NOT EXISTS namealgoindex ON tsigkeys(name, algorithm);

    -- 5. GRANT PERMISSIONS
    -- Ensure the pdns user owns everything we just created
    GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO pdns;
    GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO pdns;
