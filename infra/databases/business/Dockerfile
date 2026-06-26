# =============================================================================
# Business Database - MongoDB Container Image
# Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
# =============================================================================
# This Dockerfile builds a hardened MongoDB 7 image for the Business Database.
# It includes custom configuration, initialization scripts for user creation
# and collection schema enforcement, and runs as a non-root process where
# possible through MongoDB's built-in authorization mechanism.
#
# Oltre a mongod, l'immagine avvia (via entrypoint wrapper) un tailer del
# profiler che produce /var/log/ztaleaks/mongodb/db_access.jsonl con lo schema
# { timestamp, service, utente_connesso, tipo_operazione, collezione }.
#
# NB: il build context e' `infra/databases` (non la sottocartella business),
# cosi' da poter copiare anche gli script condivisi in `common/`.
# =============================================================================

FROM mongo:7

# Copy the custom MongoDB configuration file
COPY business/mongod.conf /etc/mongod.conf

# Copy initialization scripts into the Docker entrypoint directory.
# MongoDB executes .js files in this directory alphabetically on first startup
# (i.e., when the data directory is empty).
COPY business/init-scripts/ /docker-entrypoint-initdb.d/

# Script condivisi del tailer del profiler (entrypoint wrapper + tail loop).
COPY common/ztaleaks-entrypoint.sh /usr/local/bin/ztaleaks-entrypoint.sh
COPY common/profile-tailer.sh /usr/local/bin/profile-tailer.sh
COPY common/profile-tailer.js /usr/local/bin/profile-tailer.js
RUN chmod +x /usr/local/bin/ztaleaks-entrypoint.sh /usr/local/bin/profile-tailer.sh

# Create the ztaleaks log directory and set permissions
RUN mkdir -p /var/log/ztaleaks/mongodb && chown -R mongodb:mongodb /var/log/ztaleaks/mongodb

# Parametri del tailer del profiler (database osservato, credenziali, output).
# profiler_reader e' creato dalle init-scripts con least-privilege (find su
# nuclear_plant_db.system.profile).
ENV TARGET_DB=nuclear_plant_db \
    LOG_FILE=/var/log/ztaleaks/mongodb/db_access.jsonl \
    TAILER_URI="mongodb://profiler_reader:profilerReaderPass2026!@localhost:27017/nuclear_plant_db?authSource=nuclear_plant_db"

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
