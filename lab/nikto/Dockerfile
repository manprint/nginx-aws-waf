FROM alpine:3.22
# perl-xml-writer: required by nikto 2.6.1 at startup (not in the plan's original package list)
RUN apk add --no-cache perl perl-net-ssleay perl-xml-writer git && git clone --depth 1 --branch 2.6.1 https://github.com/sullo/nikto /opt/nikto
ENTRYPOINT ["perl", "/opt/nikto/program/nikto.pl"]
