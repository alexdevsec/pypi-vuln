FROM ubuntu:18.04
COPY apt.tar /var/cache
RUN useradd -m developer
RUN apt update && apt install -y daemontools python-pip python3-pip sudo vim 
ENV PACKAGE=none
ENV PYTHON_BIN=none
ENV OUTPUT_FILE=none
ADD inst.sh /
# CMD ["sudo","-H","-u","developer","PACKAGE=ACKAGE","/bin/bash"]
USER developer
CMD ["/inst.sh"]
# sudo","-H","-u","developer","/bin/bash"]


