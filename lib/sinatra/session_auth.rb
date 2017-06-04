require 'date'
require 'securerandom'
require 'bcrypt'

module Sinatra
  module SessionAuth
    module ModelHelpers
      def self.included(klass)
        klass.send :include, InstanceMethods
        klass.send :extend,  ClassMethods
      end 

      module InstanceMethods
        def password=(pass)
          password = pass
          self.salt = SecureRandom.base64(20)
          self.hashed_password = self.class.encrypt(password, self.salt)
        end
      end

      module ClassMethods
        def encrypt(pass, salt)
          BCrypt::Password.create(salt + pass)
        end

        def authenticate(args={})
          login, pass = args[:login], args[:password]
          u = nil
          begin
            u = self.first(:login => login)
          rescue
            u = self.where(:login => login).first
          end
          return nil if u.nil?
          return u if self.encrypt(pass, u.salt) == u.hashed_password
          nil
        end

      end
    end
    
    module Helpers
      def authorized?
        return true if session[:user]
      end

      def authorize!
        redirect '/protected/login' unless authorized?
      end

      def logout!
        session[:user] = false
      end
    end

    def self.registered(app)
      app.helpers SessionAuth::Helpers
    end
  end

  register SessionAuth
end
