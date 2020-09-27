#!/bin/bash

PASSWORD=`head -c1000 /dev/urandom | tr -dc [:alpha:][:digit:] | head -c 16; echo ;`
JWT_SECRET=`head -c1000 /dev/urandom | tr -dc [:alpha:][:digit:] | head -c 32; echo ;`
SECRET_KEY=`head -c1000 /dev/urandom | tr -dc [:alpha:][:digit:] | head -c 32; echo ;`
DB=auth_server_rust

docker run --name auth_server_postgres \
    -p 12345:5432 -e POSTGRES_PASSWORD=$PASSWORD \
            -d postgres

DATABASE_URL="postgresql://postgres:$PASSWORD@localhost:12345/postgres"

psql $DATABASE_URL -c "CREATE DATABASE $DB"

DATABASE_URL="postgresql://postgres:$PASSWORD@localhost:12345/$DB"

sudo apt-get install -y postgresql

mkdir -p ${HOME}/.config/auth_server_rust
cat > ${HOME}/.config/auth_server_rust/config.env <<EOL
DATABASE_URL=$DATABASE_URL
SENDING_EMAIL_ADDRESS=user@localhost
SECRET_PATH=${HOME}/.config/auth_server_rust/secret.bin
JWT_SECRET_PATH=${HOME}/.config/auth_server_rust/jwt_secret.bin
CALLBACK_URL=https://localhost/callback
DOMAIN=localhost
PORT=3000
HASH_ROUNDS=12
EOL

psql $DATABASE_URL < ./scripts/invitations.sql
psql $DATABASE_URL < ./scripts/users.sql
