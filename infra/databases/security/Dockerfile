# =============================================================================
# Security Database - MongoDB Container Image
# Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
# =============================================================================
# This Dockerfile builds a hardened MongoDB 7 image for the Security Database.
# It includes custom configuration, initialization scripts for user creation
# and runs as a non-root process where possible through MongoDB's built-in
# authorization mechanism.
#
# Oltre a mongod, l'immagine avvia (via entrypoint wrapper) un tailer del
# profiler che produce /var/log/ztaleaks/security-db/db_access.jsonl con lo
# schema { timestamp, service, utente_connesso, tipo_operazione, collezione }.
#
# NB: il build context e' `infra/databases` (non la sottocartella security),
# cosi' da poter copiare anche gli script condivisi in `common/`.
# =============================================================================

FROM mongo:7

# Copy the custom MongoDB configuration file
COPY security/mongod.conf /etc/mongod.conf

# Copy initialization scripts into the Docker entrypoint directory.
COPY security/db_init/ /docker-entrypoint-initdb.d/

# Script condivisi del tailer del profiler (entrypoint wrapper + tail loop).
COPY common/ztaleaks-entrypoint.sh /usr/local/bin/ztaleaks-entrypoint.sh
COPY common/profile-tailer.sh /usr/local/bin/profile-tailer.sh
COPY common/profile-tailer.js /usr/local/bin/profile-tailer.js
RUN chmod +x /usr/local/bin/ztaleaks-entrypoint.sh /usr/local/bin/profile-tailer.sh

# Create the ztaleaks log directory and set permissions
RUN mkdir -p /var/log/ztaleaks/security-db && chown -R mongodb:mongodb /var/log/ztaleaks/security-db

# Parametri del tailer del profiler. Sul security DB l'utente root ztadmin
# (MONGO_INITDB_ROOT_*) puo' leggere system.profile: nessun utente aggiuntivo.
ENV TARGET_DB=securitydb \
    LOG_FILE=/var/log/ztaleaks/security-db/db_access.jsonl \
    TAILER_URI="mongodb://ztadmin:ztpassword@localhost:27017/securitydb?authSource=admin"

# Expose the default MongoDB port
EXPOSE 27017

# Health check to verify MongoDB is responsive.
# Uses mongosh to ping the database every 30 seconds.
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD mongosh --quiet --eval "db.adminCommand('ping').ok" || exit 1

# Wrapper: avvia il tailer in background, poi exec docker-entrypoint.sh mongod.
ENTRYPOINT ["/usr/local/bin/ztaleaks-entrypoint.sh"]

# Start MongoDB with the custom configuration
CMD ["mongod", "--config", "/etc/mongod.conf"]
