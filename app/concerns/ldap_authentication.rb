module LdapAuthentication
  def self.extended(base_class)
    base_class.extend(LdapAuthentication::ClassMethods)
    base_class.send(:include, LdapAuthentication::InstanceMethods)

    base_class.class_eval do
      class << self
        alias_method_chain :authenticate, :ldap
      end

      field :from_ldap, :type => Boolean, :default => false
    end
  end

  module ClassMethods
    def authenticate_with_ldap(login, password)
      authenticated_user = ldap_login(login, password)

      if authenticated_user
        password = "not needed for ldap"
        user     = find_or_create_by_login!(login, { :email                 => authenticated_user.mail.first,
                                                     :name                  => authenticated_user.displayname.first,
                                                     :password              => password,
                                                     :password_confirmation => password,
                                                     :role                  => User::STANDARD_ROLE })
        user.update_attribute(:from_ldap, true)
        user
      else
        nil
      end
    end

    private
    # Returns a single Net::LDAP::Entry or false
    def ldap_login(login, password)
      ldap_session       = new_ldap_session(login, password)
      authenticated_user = ldap_session.bind_as({ :base     => ::Configuration.ldap_base,
                                                  :filter   => "(#{::Configuration.ldap_username_attr}=#{ login })",
                                                  :password => password })

      authenticated_user ? authenticated_user.first : false
    end

    def new_ldap_session(login, password)
      Net::LDAP.new(:host       => ::Configuration.ldap_host,
                    :port       => ::Configuration.ldap_port,
                    :encryption => ::Configuration.ldap_encryption.try(:to_sym),
                    :base       => ::Configuration.ldap_base,
                    :auth => {
                        :username => "#{::Configuration.ldap_bind_domain_name}\\#{login}",
                        :password => password,
                        :method => :simple
                      }
                    )
    end

  end

  module InstanceMethods
  end

  module Configuration
    def ldap_config(key, default = nil)
      nested_general_config :ldap, key, default
    end

    def ldap_enabled?
      ldap_config :enabled, false
    end

    def ldap_host
      ldap_config :host
    end

    def ldap_port
      ldap_config :port, 389
    end

    def ldap_base
      ldap_config :base
    end

    def ldap_encryption
      ldap_config :encryption
    end

    def ldap_username_attr
      ldap_config(:username_attr) || "uid"
    end

    def ldap_bind_domain_name
      ldap_config :bind_domain_name
    end
  end
end
