require 'test_helper'

class LdapAuthenticationTest < ActiveSupport::TestCase
  class UserWithLdap < User
    # Turning of Mongoids STI
    field(:_type, default: User, type: String)
    def self.hereditary?
      false
    end

    extend LdapAuthentication
  end

  setup do
    @existing_user   = User.make(:login => 'existing_user')
    @mock_ldap_entry = mock()
    @mock_ldap_entry.stubs(:mail => ['clowder@gmail.com'], :displayname => ['Chris Lowder'])
  end

  def test_should_create_local_user_for_new_ldap_users
    UserWithLdap.stubs(:ldap_login).returns(@mock_ldap_entry)

    assert_difference 'User.count' do
      user = UserWithLdap.authenticate("clowder", "foobar")


      assert_equal "clowder",           user.login
      assert_equal "clowder@gmail.com", user.email
      assert_equal "Chris Lowder",      user.name
      assert_equal true,                user.from_ldap
    end
  end

  def test_should_not_create_local_user_for_returning_ldap_users
    UserWithLdap.stubs(:ldap_login).returns(@mock_ldap_entry)

    assert_no_difference 'User.count' do
      user = UserWithLdap.authenticate("existing_user", "anything")

      assert_equal @existing_user, user
    end
  end

  def test_returns_nil_if_authentication_fails
    UserWithLdap.stubs(:ldap_login).returns(false)

    assert_no_difference 'User.count' do
      user = UserWithLdap.authenticate("clowder", "clowder123")
      assert_equal nil, user
    end
  end
end

