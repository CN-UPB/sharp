FROM ubuntu:trusty

RUN apt-get update
RUN apt-get install -y psmisc ethtool tcpdump python python-pip python-dev
RUN pip install python-pytun scapy netaddr

# create links
RUN ln -s /src/handover/generator/generator.py /usr/bin/generator
RUN ln -s /src/handover/generator/responder.py /usr/bin/responder
RUN ln -s /src/handover/vnf/hsl_layer.py /usr/bin/hsl_layer
RUN ln -s /src/handover/vnf/vnf_impl.py /usr/bin/vnf_impl