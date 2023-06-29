FROM python:3.10

RUN pip install neo4j

RUN mkdir /datasets
COPY datasets /datasets
COPY create_schema.py /create_schema.py
WORKDIR /

CMD ["python", "create_schema.py"]