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
          self.salt = SecureRandom.base64(20)
          self.hashed_password = BCrypt::Password.create(self.salt + pass)
        end
      end

      module ClassMethods
        def authenticate(args={})
          u = nil
          begin
            u = self.first(:login => args[:login])
          rescue
            u = self.where(:login => args[:login]).first
          end
          return nil if u.nil?
          return u if BCrypt::Password.new(u.hashed_password) == u.salt + args[:password]
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
