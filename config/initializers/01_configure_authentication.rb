Graylog2WebInterface::Application.config.authentication_stratigies = [BasicAuthentication]

if Configuration.ldap_enabled?
  Graylog2WebInterface::Application.config.authentication_strategies.unshift(LdapAuthentication)
end
