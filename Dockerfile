FROM debian:jessie

MAINTAINER Gaëtan FEREZ <gaetan@ferez.fr>

RUN apt-get update && apt-get install build-essential python3 wget python3-dev libffi-dev libssl-dev
RUN wget https://bootstrap.pypa.io/get-pip.py
RUN python3 get-pip.py
RUN pip3 install --trusted-host media --extra-index-url http://media:8080 manpki
RUN useradd -rUd /var/lib/manpki manpki