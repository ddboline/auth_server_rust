#!/bin/bash

DB=auth_server_rust

docker run -d --rm --name auth_server_postgres \
    -p 12345:5432 -e POSTGRES_PASSWORD=$PASSWORD postgres
sleep 10
DATABASE_URL="postgresql://postgres:$PASSWORD@localhost:12345/postgres"

psql $DATABASE_URL -c "CREATE DATABASE $DB"

DATABASE_URL="postgresql://postgres:$PASSWORD@localhost:12345/$DB"

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
