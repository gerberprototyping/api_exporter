FROM python:3-alpine

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY api_exporter.py ./

EXPOSE 10023
CMD [ "python", "./api_exporter.py" ]
