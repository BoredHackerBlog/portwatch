#docker build -t portwatch .
#docker run -p 8000:5000 -v /tmp/:/app/database/ portwatch
FROM ubuntu:20.04

RUN apt update

RUN apt install nmap -y
RUN apt install python3 -y
RUN apt install python3-pip -y

RUN pip3 install flask
RUN pip3 install flask-sqlalchemy
RUN pip3 install flask-admin
RUN pip3 install python3-nmap
RUN pip3 install schedule
RUN pip3 install pandas

RUN mkdir /app
RUN mkdir /app/database
COPY app.py /app/app.py
WORKDIR /app
CMD flask run --host=0.0.0.0
