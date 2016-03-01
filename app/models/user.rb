class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :token_authenticatable, :confirmable,
  # :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable, :omniauthable

  class << self
    def find_for_google_oauth2(auth)
      user = User.where(email: auth.info.email).first

      unless user
        user = User.create(name: auth.info.name,
                           provider: auth.provider,
                           uid: auth.uid,
                           email: auth.info.email,
                           token: auth.credentials.token,
                           password: Devise.friendly_token[0, 20])
      end
      user
    end
  end
end
