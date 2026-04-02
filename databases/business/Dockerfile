# =============================================================================
# Business Database - MongoDB Container Image
# Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
# =============================================================================
# This Dockerfile builds a hardened MongoDB 7 image for the Business Database.
# It includes custom configuration, initialization scripts for user creation
# and collection schema enforcement, and runs as a non-root process where
# possible through MongoDB's built-in authorization mechanism.
# =============================================================================

FROM mongo:7

# Copy the custom MongoDB configuration file
COPY mongod.conf /etc/mongod.conf

# Copy initialization scripts into the Docker entrypoint directory.
# MongoDB executes .js files in this directory alphabetically on first startup
# (i.e., when the data directory is empty).
COPY init-scripts/ /docker-entrypoint-initdb.d/

# Expose the default MongoDB port
EXPOSE 27017

# Health check to verify MongoDB is responsive.
# Uses mongosh to ping the database every 30 seconds.
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD mongosh --quiet --eval "db.adminCommand('ping').ok" || exit 1

# Start MongoDB with the custom configuration
CMD ["mongod", "--config", "/etc/mongod.conf"]