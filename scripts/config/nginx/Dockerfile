FROM nginx

EXPOSE 80 443

ENV CT_VER 0.19.5
ENV CT_URL https://releases.hashicorp.com/consul-template/${CT_VER}/consul-template_${CT_VER}_linux_amd64.zip
RUN curl -O $CT_URL && unzip consul-template_${CT_VER}_linux_amd64.zip -d /usr/local/bin

ADD nginx.service /etc/service/nginx/run
ADD consul-template.service /etc/service/consul-template/run
RUN chmod +x /etc/service/nginx/run
RUN chmod +x /etc/service/consul-template/run


ADD nginx.conf /etc/nginx/conf.d/default.conf
ADD consul-template.hcl /etc/consul-template.hcl

CMD ["/usr/bin/runsvdir", "/etc/service"]
