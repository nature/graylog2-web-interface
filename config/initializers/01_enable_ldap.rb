Configuration.extend LdapAuthentication::Configuration

if Configuration.ldap_enabled?
  User.extend LdapAuthentication
end
