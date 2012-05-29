class LdapAuthentication
  def initialize(login, password)
    @login    = login
    @password = password
  end

  def credentials
    # Make sure that we dont allow users to bind with a blank password, even if we
    # have anonymous binding turned on.
    # https://github.com/ruby-ldap/ruby-net-ldap/issues/5
    @credentials ||= if @password.present? && user
      email = user['mail'].first
      name  = user[::Configuration.ldap_displayname_attribute].first
      Authenticator::Credentials.new(@login, email, name, true)
    end
  end

  private
  def user
    @user ||= Array(session.bind_as(bind_args)).first
  end

  # This is where LDAP jumps up and punches you in the face, all the while
  # screaming "You never gunna get this, your wasting your time!".
  def bind_args
    user_filter = "#{ ::Configuration.ldap_username_attribute }=#{ @login }"
    args        = { :base     => ::Configuration.ldap_base,
                    :filter   => "(#{ user_filter })",
                    :password => @password }

    unless ::Configuration.ldap_can_search_anonymously?
      # If you can't search your LDAP directory anonymously we'll try and
      # authenticate you with your user dn before we try and search for your
      # account (dn example. `uid=clowder,ou=People,dc=mycompany,dc=com`).
      user_dn = [user_filter, ::Configuration.ldap_base].join(',')
      args.merge!({ :auth => { :username => user_dn, :password => @password, :method => :simple } })
    end

    args
  end

  def session
    Net::LDAP.new(:host       => ::Configuration.ldap_host,
                  :port       => ::Configuration.ldap_port,
                  :encryption => ::Configuration.ldap_encryption,
                  :base       => ::Configuration.ldap_base)
  end
end
