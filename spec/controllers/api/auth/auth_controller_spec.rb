require 'rails_helper'

RSpec.describe Api::Auth::AuthController, type: :controller do
  describe 'POST #register' do
    let(:valid_params) do
      {
        user: {
          email: 'test@example.com',
          password: 'password123',
          password_confirmation: 'password123'
        }
      }
    end

    context 'with valid parameters' do
      it 'creates a new user' do
        expect {
          post :register, params: valid_params
        }.to change(User, :count).by(1)
      end

      it 'returns success response' do
        post :register, params: valid_params
        expect(response).to have_http_status(:created)
      end

      it 'returns correct JSON structure' do
        post :register, params: valid_params
        json_response = JSON.parse(response.body)
        
        expect(json_response).to include('message' => 'User registered successfully')
        expect(json_response['user']).to include('id', 'email')
        expect(json_response['user']['email']).to eq('test@example.com')
      end

      it 'downcases email before saving' do
        post :register, params: valid_params.merge(user: { email: 'UPPERCASE@EXAMPLE.COM', password: 'password123', password_confirmation: 'password123' })
        expect(User.last.email).to eq('uppercase@example.com')
      end
    end

    context 'with invalid parameters' do
      it 'does not create a user with invalid email' do
        expect {
          post :register, params: { user: { email: 'invalid-email', password: 'password123', password_confirmation: 'password123' } }
        }.not_to change(User, :count)
      end

      it 'returns unprocessable entity status' do
        post :register, params: { user: { email: 'invalid-email', password: 'password123', password_confirmation: 'password123' } }
        expect(response).to have_http_status(:unprocessable_entity)
      end

      it 'returns validation errors' do
        post :register, params: { user: { email: 'invalid-email', password: 'password123', password_confirmation: 'password123' } }
        json_response = JSON.parse(response.body)
        expect(json_response['errors']).to include('Email is invalid')
      end

      it 'does not create a user with short password' do
        expect {
          post :register, params: { user: { email: 'test@example.com', password: '123', password_confirmation: '123' } }
        }.not_to change(User, :count)
      end

      it 'returns password length error' do
        post :register, params: { user: { email: 'test@example.com', password: '123', password_confirmation: '123' } }
        json_response = JSON.parse(response.body)
        expect(json_response['errors']).to include('Password is too short (minimum is 6 characters)')
      end

      it 'does not create a user with mismatched password confirmation' do
        expect {
          post :register, params: { user: { email: 'test@example.com', password: 'password123', password_confirmation: 'different' } }
        }.not_to change(User, :count)
      end

      it 'returns password confirmation error' do
        post :register, params: { user: { email: 'test@example.com', password: 'password123', password_confirmation: 'different' } }
        json_response = JSON.parse(response.body)
        expect(json_response['errors']).to include("Password confirmation doesn't match Password")
      end

      it 'does not create a user with duplicate email' do
        create(:user, email: 'test@example.com')
        expect {
          post :register, params: valid_params
        }.not_to change(User, :count)
      end

      it 'returns duplicate email error' do
        create(:user, email: 'test@example.com')
        post :register, params: valid_params
        json_response = JSON.parse(response.body)
        expect(json_response['errors']).to include('Email has already been taken')
      end

      it 'does not create a user with missing email' do
        expect {
          post :register, params: { user: { password: 'password123', password_confirmation: 'password123' } }
        }.not_to change(User, :count)
      end

      it 'returns missing email error' do
        post :register, params: { user: { password: 'password123', password_confirmation: 'password123' } }
        json_response = JSON.parse(response.body)
        expect(json_response['errors']).to include("Email can't be blank")
      end
    end
  end

  describe 'POST #login' do
    let!(:user) { create(:user, email: 'test@example.com', password: 'password123', password_confirmation: 'password123') }

    context 'with valid credentials' do
      it 'returns success response' do
        post :login, params: { email: 'test@example.com', password: 'password123' }
        expect(response).to have_http_status(:ok)
      end

      it 'returns correct JSON structure with token' do
        post :login, params: { email: 'test@example.com', password: 'password123' }
        json_response = JSON.parse(response.body)
        
        expect(json_response).to include('message' => 'Login successful')
        expect(json_response['user']).to include('id', 'email')
        expect(json_response['user']['email']).to eq('test@example.com')
        expect(json_response).to include('token')
        expect(json_response['token']).to be_present
      end

      it 'generates a valid JWT token' do
        post :login, params: { email: 'test@example.com', password: 'password123' }
        json_response = JSON.parse(response.body)
        token = json_response['token']
        
        payload = JwtService.decode(token)
        expect(payload).to be_present
        expect(payload['user_id']).to eq(user.id)
        expect(payload['email']).to eq(user.email)
      end

      it 'authenticates with case-insensitive email' do
        post :login, params: { email: 'TEST@EXAMPLE.COM', password: 'password123' }
        expect(response).to have_http_status(:ok)
      end
    end

    context 'with invalid credentials' do
      it 'returns unauthorized status with wrong password' do
        post :login, params: { email: 'test@example.com', password: 'wrong_password' }
        expect(response).to have_http_status(:unauthorized)
      end

      it 'returns error message with wrong password' do
        post :login, params: { email: 'test@example.com', password: 'wrong_password' }
        json_response = JSON.parse(response.body)
        expect(json_response['error']).to eq('Invalid email or password')
      end

      it 'returns unauthorized status with non-existent email' do
        post :login, params: { email: 'nonexistent@example.com', password: 'password123' }
        expect(response).to have_http_status(:unauthorized)
      end

      it 'returns error message with non-existent email' do
        post :login, params: { email: 'nonexistent@example.com', password: 'password123' }
        json_response = JSON.parse(response.body)
        expect(json_response['error']).to eq('Invalid email or password')
      end

      it 'returns unauthorized status with empty password' do
        post :login, params: { email: 'test@example.com', password: '' }
        expect(response).to have_http_status(:unauthorized)
      end

      it 'returns unauthorized status with empty email' do
        post :login, params: { email: '', password: 'password123' }
        expect(response).to have_http_status(:unauthorized)
      end

      it 'returns unauthorized status with nil password' do
        post :login, params: { email: 'test@example.com', password: nil }
        expect(response).to have_http_status(:unauthorized)
      end

      it 'returns unauthorized status with nil email' do
        post :login, params: { email: nil, password: 'password123' }
        expect(response).to have_http_status(:unauthorized)
      end
    end
  end

  describe 'request format' do
    it 'accepts JSON requests' do
      post :register, params: { user: { email: 'test@example.com', password: 'password123', password_confirmation: 'password123' } }
      expect(response.content_type).to include('application/json')
    end

    it 'returns JSON responses' do
      post :register, params: { user: { email: 'test@example.com', password: 'password123', password_confirmation: 'password123' } }
      expect { JSON.parse(response.body) }.not_to raise_error
    end
  end
end 