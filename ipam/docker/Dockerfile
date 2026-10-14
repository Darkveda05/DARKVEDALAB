# ---------------------------------------------------------------
# DarkVeda IPAM
# ---------------------------------------------------------------
FROM php:8.3-apache

LABEL org.opencontainers.image.title="DarkVeda IPAM" \
      org.opencontainers.image.description="Self-hosted IP Address Management with SNMP discovery, LLDP/CDP topology, rack visualisation and Zabbix monitoring" \
      org.opencontainers.image.licenses="MIT"

# iputils-ping    -> discovery sweeps
# libsnmp-dev/snmp-> SNMP polling and LLDP/CDP topology
RUN apt-get update && apt-get install -y --no-install-recommends \
        libsnmp-dev \
        snmp \
        iputils-ping \
        default-mysql-client \
    && rm -rf /var/lib/apt/lists/* \
    && docker-php-ext-install pdo_mysql sockets snmp \
    && a2enmod rewrite headers

# Sensible PHP defaults for document uploads (32 MB limit in the app)
RUN { \
        echo 'upload_max_filesize = 40M'; \
        echo 'post_max_size = 48M'; \
        echo 'memory_limit = 256M'; \
        echo 'max_execution_time = 300'; \
        echo 'expose_php = Off'; \
    } > /usr/local/etc/php/conf.d/darkveda.ini

COPY docker/apache-vhost.conf /etc/apache2/sites-available/000-default.conf
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY . /var/www/html/

# The installer is for bare-metal setups; the container bootstraps itself.
RUN rm -f /var/www/html/public/install.php \
    && mkdir -p /var/www/html/public/uploads/rack /var/www/html/public/uploads/docs \
    && chown -R www-data:www-data /var/www/html/public/uploads /var/www/html/config \
    && chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /var/www/html
EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD php -r 'exit(@file_get_contents("http://127.0.0.1/?page=login") ? 0 : 1);'

ENTRYPOINT ["entrypoint.sh"]
CMD ["apache2-foreground"]
