FROM python:3.10-slim

RUN apt update -y && apt install python3-urllib3 -y

ENV PYTHONUNBUFFERED True

ENV APP_HOME /app
WORKDIR $APP_HOME
COPY . ./

RUN pip install --no-cache-dir -r requirements.txt
RUN ln -sf /usr/share/zoneinfo/America/Sao_Paulo /etc/localtime

ENV TZ=America/Sao_Paulo
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

CMD exec python3 /app/run.py