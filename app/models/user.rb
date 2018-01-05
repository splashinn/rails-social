class User < ApplicationRecord
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
  validates :name, presence: false, length: { maximum: 255 }
  validates :username, presence: false, length: { maximum: 50 }
  validates :email, presence: true, length: { maximum: 255 }, format: { with: VALID_EMAIL_REGEX }, uniqueness: { case_sensitive: false }
  has_secure_password(validations: false)
  validates :password, presence: false, length: { minimum: 0 }, allow_blank: true
  before_save { self.email = email.downcase }

  has_many :identities

  # Assign an API key on create
  before_create :set_api_key
  before_create :set_username

  def set_api_key
    self.api_key = generate_api_key
  end

  def set_username
    self.username = self.email if !self.username.present?
  end

  # Generate a unique API key
  def generate_api_key
    loop do
      token = SecureRandom.base64.tr('+/=', 'Qrt')
      break token unless User.exists?(api_key: token)
    end
  end

  def self.from_omniauth(auth)
    where(email: auth.info.email).first_or_initialize.tap do |user|
      user.email = auth.info.email
      user.name = auth.info.name
      user.save!

      user.identities.where(provider: auth.provider, uid: auth.uid).first_or_initialize.tap do |identity|
          identity.provider = auth.provider
          identity.uid = auth.uid
          identity.name = auth.info.name
          identity.email = auth.info.email
          identity.image = auth.info.image
          identity.access_token = auth.credentials.token
          identity.oauth_expires_at = Time.at(auth.credentials.expires_at)
          identity.raw = auth.to_json
          identity.save!
      end
    end
  end
end
