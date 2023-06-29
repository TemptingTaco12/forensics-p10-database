FROM neo4j:5.9.0-community

RUN mkdir datasets
COPY datasets /var/lib/neo4j/import/datasets