require 'rails_helper'

RSpec.describe 'API Auth', type: :request do
  describe 'POST /api/auth/register' do
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
          post '/api/auth/register', params: valid_params.to_json, headers: { 'Content-Type' => 'application/json' }
        }.to change(User, :count).by(1)
      end

      it 'returns 201 status' do
        post '/api/auth/register', params: valid_params.to_json, headers: { 'Content-Type' => 'application/json' }
        expect(response).to have_http_status(:created)
      end

      it 'returns correct JSON response' do
        post '/api/auth/register', params: valid_params.to_json, headers: { 'Content-Type' => 'application/json' }
        json_response = JSON.parse(response.body)
        
        expect(json_response).to include('message' => 'User registered successfully')
        expect(json_response['user']).to include('id', 'email')
        expect(json_response['user']['email']).to eq('test@example.com')
      end

      it 'downcases email before saving' do
        post '/api/auth/register', params: valid_params.merge(user: { email: 'UPPERCASE@EXAMPLE.COM', password: 'password123', password_confirmation: 'password123' }).to_json, headers: { 'Content-Type' => 'application/json' }
        expect(User.last.email).to eq('uppercase@example.com')
      end
    end

    context 'with invalid parameters' do
      it 'returns 422 status for invalid email' do
        post '/api/auth/register', params: { user: { email: 'invalid-email', password: 'password123', password_confirmation: 'password123' } }.to_json, headers: { 'Content-Type' => 'application/json' }
        expect(response).to have_http_status(:unprocessable_entity)
      end

      it 'returns validation errors for invalid email' do
        post '/api/auth/register', params: { user: { email: 'invalid-email', password: 'password123', password_confirmation: 'password123' } }.to_json, headers: { 'Content-Type' => 'application/json' }
        json_response = JSON.parse(response.body)
        expect(json_response['errors']).to include('Email is invalid')
      end

      it 'returns 422 status for short password' do
        post '/api/auth/register', params: { user: { email: 'test@example.com', password: '123', password_confirmation: '123' } }.to_json, headers: { 'Content-Type' => 'application/json' }
        expect(response).to have_http_status(:unprocessable_entity)
      end

      it 'returns validation errors for short password' do
        post '/api/auth/register', params: { user: { email: 'test@example.com', password: '123', password_confirmation: '123' } }.to_json, headers: { 'Content-Type' => 'application/json' }
        json_response = JSON.parse(response.body)
        expect(json_response['errors']).to include('Password is too short (minimum is 6 characters)')
      end

      it 'returns 422 status for duplicate email' do
        create(:user, email: 'test@example.com')
        post '/api/auth/register', params: valid_params.to_json, headers: { 'Content-Type' => 'application/json' }
        expect(response).to have_http_status(:unprocessable_entity)
      end

      it 'returns validation errors for duplicate email' do
        create(:user, email: 'test@example.com')
        post '/api/auth/register', params: valid_params.to_json, headers: { 'Content-Type' => 'application/json' }
        json_response = JSON.parse(response.body)
        expect(json_response['errors']).to include('Email has already been taken')
      end
    end
  end

  describe 'POST /api/auth/login' do
    let!(:user) { create(:user, email: 'test@example.com', password: 'password123', password_confirmation: 'password123') }

    context 'with valid credentials' do
      it 'returns 200 status' do
        post '/api/auth/login', params: { email: 'test@example.com', password: 'password123' }.to_json, headers: { 'Content-Type' => 'application/json' }
        expect(response).to have_http_status(:ok)
      end

      it 'returns correct JSON response with token' do
        post '/api/auth/login', params: { email: 'test@example.com', password: 'password123' }.to_json, headers: { 'Content-Type' => 'application/json' }
        json_response = JSON.parse(response.body)
        
        expect(json_response).to include('message' => 'Login successful')
        expect(json_response['user']).to include('id', 'email')
        expect(json_response['user']['email']).to eq('test@example.com')
        expect(json_response).to include('token')
        expect(json_response['token']).to be_present
      end

      it 'generates a valid JWT token' do
        post '/api/auth/login', params: { email: 'test@example.com', password: 'password123' }.to_json, headers: { 'Content-Type' => 'application/json' }
        json_response = JSON.parse(response.body)
        token = json_response['token']
        
        payload = JwtService.decode(token)
        expect(payload).to be_present
        expect(payload['user_id']).to eq(user.id)
        expect(payload['email']).to eq(user.email)
        expect(payload['exp']).to be_present
      end

      it 'authenticates with case-insensitive email' do
        post '/api/auth/login', params: { email: 'TEST@EXAMPLE.COM', password: 'password123' }.to_json, headers: { 'Content-Type' => 'application/json' }
        expect(response).to have_http_status(:ok)
      end
    end

    context 'with invalid credentials' do
      it 'returns 401 status with wrong password' do
        post '/api/auth/login', params: { email: 'test@example.com', password: 'wrong_password' }.to_json, headers: { 'Content-Type' => 'application/json' }
        expect(response).to have_http_status(:unauthorized)
      end

      it 'returns error message with wrong password' do
        post '/api/auth/login', params: { email: 'test@example.com', password: 'wrong_password' }.to_json, headers: { 'Content-Type' => 'application/json' }
        json_response = JSON.parse(response.body)
        expect(json_response['error']).to eq('Invalid email or password')
      end

      it 'returns 401 status with non-existent email' do
        post '/api/auth/login', params: { email: 'nonexistent@example.com', password: 'password123' }.to_json, headers: { 'Content-Type' => 'application/json' }
        expect(response).to have_http_status(:unauthorized)
      end

      it 'returns error message with non-existent email' do
        post '/api/auth/login', params: { email: 'nonexistent@example.com', password: 'password123' }.to_json, headers: { 'Content-Type' => 'application/json' }
        json_response = JSON.parse(response.body)
        expect(json_response['error']).to eq('Invalid email or password')
      end

      it 'returns 401 status with empty password' do
        post '/api/auth/login', params: { email: 'test@example.com', password: '' }.to_json, headers: { 'Content-Type' => 'application/json' }
        expect(response).to have_http_status(:unauthorized)
      end

      it 'returns 401 status with empty email' do
        post '/api/auth/login', params: { email: '', password: 'password123' }.to_json, headers: { 'Content-Type' => 'application/json' }
        expect(response).to have_http_status(:unauthorized)
      end
    end
  end
end 