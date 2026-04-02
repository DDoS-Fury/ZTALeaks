FROM mongo:7

COPY mongod.conf /etc/mongod.conf
COPY init-scripts/ /docker-entrypoint-initdb.d/

EXPOSE 27017

CMD ["mongod", "--config", "/etc/mongod.conf"]