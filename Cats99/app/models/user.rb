class User < ApplicationRecord
  
  
  validates :username, uniqueness: true, presence: true 
  validates :password, length: { minimum: 6, allow_nil: true }
  validates :session_token, uniqueness: true 
  
  after_initialize :ensure_session_token
  attr_reader :password
  
  def reset_session_token 
    self.session_token = SecureRandom::urlsafe_base64(16)
    self.save!
    self.session_token
  end 
  
  def password=(pw)
    @password = pw 
    self.password_digest = BCrypt::Password.create(pw)
  end 
  
  def is_password?(pw)
    BCrypt::Password.new(password_digest).is_password?(pw)
  end 
  
  def self.find_by_credentials(user_name, password)
    user = User.find_by(username: user_name)
    if user && user.is_password?(password)
      user
    else 
      nil 
    end 
  end 
  
  def ensure_session_token
    self.session_token ||= SecureRandom::urlsafe_base64(16)
  end 
  
end
