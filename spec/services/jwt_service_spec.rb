require 'rails_helper'

RSpec.describe JwtService do
  let(:user) { create(:user, email: 'test@example.com') }

  describe '.generate_token' do
    it 'generates a token with user information' do
      token = described_class.generate_token(user)
      expect(token).to be_present
      
      payload = described_class.decode(token)
      expect(payload['user_id']).to eq(user.id)
      expect(payload['email']).to eq(user.email)
      expect(payload['exp']).to be_present
    end

    it 'sets expiration to 24 hours from now' do
      token = described_class.generate_token(user)
      payload = described_class.decode(token)
      
      expect(payload['exp']).to be_within(60).of(24.hours.from_now.to_i)
    end
  end

  describe '.encode' do
    it 'encodes a payload into a JWT token' do
      payload = { user_id: 1, email: 'test@example.com' }
      token = described_class.encode(payload)
      
      expect(token).to be_present
      expect(token).to be_a(String)
    end
  end

  describe '.decode' do
    let(:payload) { { user_id: 1, email: 'test@example.com' } }
    let(:token) { described_class.encode(payload) }

    it 'decodes a valid JWT token' do
      decoded_payload = described_class.decode(token)
      expect(decoded_payload).to eq(payload.stringify_keys)
    end

    it 'returns nil for invalid token' do
      result = described_class.decode('invalid_token')
      expect(result).to be_nil
    end

    it 'returns nil for expired token' do
      expired_payload = { user_id: 1, exp: 1.hour.ago.to_i }
      expired_token = described_class.encode(expired_payload)
      
      result = described_class.decode(expired_token)
      expect(result).to be_nil
    end

    it 'returns nil for token with wrong signature' do
      # Create a token with different secret
      different_secret_token = JWT.encode(payload, 'different_secret', 'HS256')
      
      result = described_class.decode(different_secret_token)
      expect(result).to be_nil
    end
  end

  describe 'token structure' do
    it 'uses HS256 algorithm' do
      token = described_class.generate_token(user)
      decoded_token = JWT.decode(token, described_class::SECRET_KEY, false)
      expect(decoded_token[1]['alg']).to eq('HS256')
    end

    it 'includes user_id in payload' do
      token = described_class.generate_token(user)
      payload = described_class.decode(token)
      expect(payload['user_id']).to eq(user.id)
    end

    it 'includes email in payload' do
      token = described_class.generate_token(user)
      payload = described_class.decode(token)
      expect(payload['email']).to eq(user.email)
    end
  end
end 