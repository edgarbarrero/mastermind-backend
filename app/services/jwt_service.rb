require 'jwt'

class JwtService
  SECRET_KEY = Rails.application.credentials.secret_key_base || 'your-secret-key'
  ALGORITHM = 'HS256'

  def self.encode(payload)
    JWT.encode(payload, SECRET_KEY, ALGORITHM)
  end

  def self.decode(token)
    JWT.decode(token, SECRET_KEY, true, { algorithm: ALGORITHM })[0]
  rescue JWT::DecodeError, JWT::ExpiredSignature
    nil
  end

  def self.generate_token(user)
    payload = {
      user_id: user.id,
      email: user.email,
      exp: 24.hours.from_now.to_i
    }
    encode(payload)
  end
end 